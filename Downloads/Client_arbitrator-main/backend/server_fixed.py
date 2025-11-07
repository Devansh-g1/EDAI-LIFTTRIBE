from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from datetime import datetime, timezone, timedelta
import jwt
import bcrypt
import uuid

# Create the main app
app = FastAPI()
api_router = APIRouter(prefix="/api")
security = HTTPBearer()

# Configuration
JWT_SECRET = "temp-secret-key-change-in-production"
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24
ARBITRATOR_WALLET = "0x6A413e4C59CFB5D4544D5ecA74dacf7848b3a483"
ARBITRATOR_EMAIL = "devanshgoyal1234@gmail.com"

# In-memory storage
users_db = {}
jobs_db = {}
escrow_db = {}

# Models
class UserRegister(BaseModel):
    email: str
    password: str
    name: str

class UserLogin(BaseModel):
    email: str
    password: str

class RoleSwitch(BaseModel):
    role: str  # "client" or "freelancer"

class JobCreate(BaseModel):
    title: str
    description: str
    budget: float
    deadline: Optional[str] = None
    skills_required: Optional[List[str]] = []

class FreelancerProfile(BaseModel):
    bio: Optional[str] = None
    skills: Optional[List[str]] = []
    hourly_rate: Optional[float] = None
    portfolio_link: Optional[str] = None
    github_link: Optional[str] = None

class JobApplication(BaseModel):
    job_id: str
    proposal: str
    proposed_rate: float

# Helper functions
def create_token(user_data: dict) -> str:
    payload = {
        "user_id": user_data["id"],
        "email": user_data["email"],
        "role": user_data["active_role"],
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Health check
@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": "in_memory",
        "service": "cryptogig-backend",
        "arbitrator_wallet": ARBITRATOR_WALLET
    }

# Authentication endpoints
@api_router.post("/auth/register")
async def register(user: UserRegister):
    if user.email in users_db:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Hash password
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
    
    # Create user with default role as client
    user_id = str(uuid.uuid4())
    users_db[user.email] = {
        "id": user_id,
        "email": user.email,
        "name": user.name,
        "password": hashed_password,
        "role": "client",  # Default role
        "active_role": "client",  # Current active role
        "email_verified": True,  # Auto-verify for now
        "wallet_address": None,
        "bio": None,
        "skills": [],
        "hourly_rate": None,
        "portfolio_link": None,
        "github_link": None,
        "rating": 0.0,
        "completed_jobs": 0,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    # Create token
    token = create_token(users_db[user.email])
    
    return {
        "message": "User registered successfully",
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user_id,
            "email": user.email,
            "name": user.name,
            "role": "client",
            "active_role": "client",
            "email_verified": True
        }
    }

@api_router.post("/auth/login")
async def login(user: UserLogin):
    if user.email not in users_db:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    stored_user = users_db[user.email]
    
    # Check password
    if not bcrypt.checkpw(user.password.encode('utf-8'), stored_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create token
    token = create_token(stored_user)
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": stored_user["id"],
            "email": stored_user["email"],
            "name": stored_user["name"],
            "role": stored_user["role"],
            "active_role": stored_user["active_role"],
            "email_verified": stored_user.get("email_verified", True),
            "wallet_address": stored_user.get("wallet_address"),
            "hourly_rate": stored_user.get("hourly_rate")
        }
    }

@api_router.get("/auth/me")
async def get_current_user(current_user: dict = Depends(verify_token)):
    email = current_user["email"]
    if email not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    
    user = users_db[email]
    return {
        "id": user["id"],
        "email": user["email"],
        "name": user["name"],
        "role": user["role"],
        "active_role": user["active_role"],
        "email_verified": user.get("email_verified", True),
        "wallet_address": user.get("wallet_address"),
        "bio": user.get("bio"),
        "skills": user.get("skills", []),
        "hourly_rate": user.get("hourly_rate"),
        "portfolio_link": user.get("portfolio_link"),
        "github_link": user.get("github_link"),
        "rating": user.get("rating", 0.0),
        "completed_jobs": user.get("completed_jobs", 0)
    }

# Role switching
@api_router.post("/auth/switch-role")
async def switch_role(role_data: RoleSwitch, current_user: dict = Depends(verify_token)):
    email = current_user["email"]
    if email not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    
    if role_data.role not in ["client", "freelancer"]:
        raise HTTPException(status_code=400, detail="Invalid role")
    
    # Update active role
    users_db[email]["active_role"] = role_data.role
    
    # Create new token with updated role
    token = create_token(users_db[email])
    
    return {
        "message": f"Switched to {role_data.role} role",
        "access_token": token,
        "token_type": "bearer",
        "active_role": role_data.role
    }

# Profile endpoints
@api_router.put("/profile/freelancer")
async def update_freelancer_profile(profile: FreelancerProfile, current_user: dict = Depends(verify_token)):
    email = current_user["email"]
    if email not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Update profile
    if profile.bio:
        users_db[email]["bio"] = profile.bio
    if profile.skills:
        users_db[email]["skills"] = profile.skills
    if profile.hourly_rate is not None:
        users_db[email]["hourly_rate"] = profile.hourly_rate
    if profile.portfolio_link:
        users_db[email]["portfolio_link"] = profile.portfolio_link
    if profile.github_link:
        users_db[email]["github_link"] = profile.github_link
    
    return {"message": "Profile updated successfully"}

# Job endpoints
@api_router.post("/jobs")
async def create_job(job: JobCreate, current_user: dict = Depends(verify_token)):
    if current_user["role"] != "client":
        raise HTTPException(status_code=403, detail="Only clients can create jobs")
    
    job_id = str(uuid.uuid4())
    jobs_db[job_id] = {
        "id": job_id,
        "title": job.title,
        "description": job.description,
        "budget": job.budget,
        "deadline": job.deadline,
        "skills_required": job.skills_required or [],
        "client_id": current_user["user_id"],
        "client_email": current_user["email"],
        "status": "open",
        "freelancer_id": None,
        "applications": [],
        "escrow_status": "pending",
        "arbitrator_wallet": ARBITRATOR_WALLET,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    return {
        "message": "Job created successfully",
        "job_id": job_id,
        "job": jobs_db[job_id]
    }

@api_router.get("/jobs")
async def get_jobs(status: Optional[str] = None):
    filtered_jobs = []
    for job in jobs_db.values():
        if status is None or job["status"] == status:
            filtered_jobs.append(job)
    return {"jobs": filtered_jobs}

@api_router.get("/jobs/{job_id}")
async def get_job(job_id: str):
    if job_id not in jobs_db:
        raise HTTPException(status_code=404, detail="Job not found")
    return jobs_db[job_id]

@api_router.post("/jobs/{job_id}/apply")
async def apply_to_job(job_id: str, application: JobApplication, current_user: dict = Depends(verify_token)):
    if current_user["role"] != "freelancer":
        raise HTTPException(status_code=403, detail="Only freelancers can apply to jobs")
    
    if job_id not in jobs_db:
        raise HTTPException(status_code=404, detail="Job not found")
    
    job = jobs_db[job_id]
    if job["status"] != "open":
        raise HTTPException(status_code=400, detail="Job is not open for applications")
    
    # Add application
    application_data = {
        "freelancer_id": current_user["user_id"],
        "freelancer_email": current_user["email"],
        "proposal": application.proposal,
        "proposed_rate": application.proposed_rate,
        "applied_at": datetime.now(timezone.utc).isoformat()
    }
    
    job["applications"].append(application_data)
    
    return {"message": "Application submitted successfully"}

# Community/Marketplace endpoints
@api_router.get("/freelancers")
async def get_freelancers(skill: Optional[str] = None):
    freelancers = []
    for user in users_db.values():
        if user.get("active_role") == "freelancer" or "freelancer" in user.get("role", ""):
            freelancer_data = {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "bio": user.get("bio"),
                "skills": user.get("skills", []),
                "hourly_rate": user.get("hourly_rate"),
                "rating": user.get("rating", 0.0),
                "completed_jobs": user.get("completed_jobs", 0),
                "portfolio_link": user.get("portfolio_link"),
                "github_link": user.get("github_link")
            }
            
            # Filter by skill if provided
            if skill is None or skill in user.get("skills", []):
                freelancers.append(freelancer_data)
    
    return {"freelancers": freelancers}

# Wallet endpoints
@api_router.post("/wallet/link")
async def link_wallet(wallet_data: dict, current_user: dict = Depends(verify_token)):
    email = current_user["email"]
    if email not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    
    users_db[email]["wallet_address"] = wallet_data.get("wallet_address")
    
    return {"message": "Wallet linked successfully"}

# Include router
app.include_router(api_router)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
