from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import jwt
from datetime import datetime, timedelta
import bcrypt
import uuid

app = FastAPI()

# In-memory storage (for demo only)
users_db = {}
jobs_db = {}

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class UserLogin(BaseModel):
    email: str
    password: str

class UserCreate(BaseModel):
    email: str
    password: str
    name: str
    role: str

# Helper functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user_id: str) -> str:
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, 'demo-secret', algorithm='HS256')

# Create demo accounts
demo_users = [
    {"email": "client@cryptogig.com", "password": "test123", "name": "Demo Client", "role": "client"},
    {"email": "freelancer@cryptogig.com", "password": "test123", "name": "Demo Freelancer", "role": "freelancer"},
    {"email": "devanshgoyal1234@gmail.com", "password": "test123", "name": "Demo Arbitrator", "role": "arbitrator"}
]

for user_data in demo_users:
    user_id = str(uuid.uuid4())
    users_db[user_id] = {
        'id': user_id,
        'email': user_data['email'],
        'password_hash': hash_password(user_data['password']),
        'name': user_data['name'],
        'role': user_data['role'],
        'active_role': user_data['role'],
        'wallet_address': None
    }

@app.get("/")
async def root():
    return {"message": "CryptoGig Demo API", "mode": "demo"}

@app.post("/api/auth/login")
async def login(credentials: UserLogin):
    for user in users_db.values():
        if user['email'] == credentials.email and verify_password(credentials.password, user['password_hash']):
            token = create_token(user['id'])
            return {
                'token': token,
                'user': {
                    'id': user['id'],
                    'email': user['email'],
                    'name': user['name'],
                    'role': user['role'],
                    'active_role': user.get('active_role', user['role']),
                    'wallet_address': user.get('wallet_address')
                }
            }
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/api/auth/register")
async def register(user_data: UserCreate):
    # Check if user exists
    for user in users_db.values():
        if user['email'] == user_data.email:
            raise HTTPException(status_code=400, detail="Email already registered")
    
    user_id = str(uuid.uuid4())
    users_db[user_id] = {
        'id': user_id,
        'email': user_data.email,
        'password_hash': hash_password(user_data.password),
        'name': user_data.name,
        'role': user_data.role,
        'active_role': user_data.role,
        'wallet_address': None
    }
    
    token = create_token(user_id)
    return {
        'token': token,
        'user': {
            'id': user_id,
            'email': user_data.email,
            'name': user_data.name,
            'role': user_data.role
        }
    }

@app.get("/api/auth/me")
async def get_me():
    # For demo, return first user
    if users_db:
        user = list(users_db.values())[0]
        return {
            'id': user['id'],
            'email': user['email'],
            'name': user['name'],
            'role': user['role'],
            'active_role': user.get('active_role', user['role']),
            'wallet_address': user.get('wallet_address')
        }
    raise HTTPException(status_code=401, detail="Not authenticated")

@app.get("/api/jobs")
async def get_jobs():
    return []

@app.get("/api/stats")
async def get_stats():
    return {"total_jobs": 0, "active_jobs": 0}

if __name__ == "__main__":
    print("🎭 Demo Mode: Using in-memory storage")
    print("📋 Demo Accounts:")
    print("   Client: client@cryptogig.com / test123")
    print("   Freelancer: freelancer@cryptogig.com / test123")
    print("   Arbitrator: devanshgoyal1234@gmail.com / test123")
    uvicorn.run(app, host="0.0.0.0", port=8000)
