print("=" * 60)
print("STARTING CRYPTOGIG BACKEND SERVER")
print("=" * 60)

from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path

print("✅ Imports successful")
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import bcrypt
import jwt
from web3 import Web3
from enum import Enum
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# MongoDB connection
mongo_url = os.environ.get('MONGO_URL')
if not mongo_url:
    logger.error("MONGO_URL environment variable is not set!")
    raise ValueError("MONGO_URL environment variable is required")

logger.info(f"Connecting to MongoDB...")
try:
    client = AsyncIOMotorClient(mongo_url, serverSelectionTimeoutMS=5000)
    db = client[os.environ.get('DB_NAME', 'cryptogig_db')]
    logger.info("MongoDB client created successfully")
except Exception as e:
    logger.error(f"Failed to create MongoDB client: {e}")
    raise

# Web3 setup
CONTRACT_ADDRESS = os.environ.get('CONTRACT_ADDRESS', '')
POLYGON_RPC = os.environ.get('POLYGON_AMOY_RPC', 'https://rpc-amoy.polygon.technology')
w3 = Web3(Web3.HTTPProvider(POLYGON_RPC))

# JWT setup
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-this')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = 24

# Arbitrator configuration
ARBITRATOR_EMAIL = "devanshgoyal1234@gmail.com"
ARBITRATOR_WALLET = "0x6A413e4C59CFB5D4544D5ecA74dacf7848b3a483"

# Create the main app
app = FastAPI()
api_router = APIRouter(prefix="/api")
security = HTTPBearer()

# Enums
class UserRole(str, Enum):
    CLIENT = "client"
    FREELANCER = "freelancer"
    ARBITRATOR = "arbitrator"

class JobStatus(str, Enum):
    CREATED = "created"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    DISPUTED = "disputed"
    RESOLVED = "resolved"
    CANCELLED = "cancelled"

# Models
class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    name: str
    role: UserRole
    active_role: UserRole  # Current active role for role switching
    wallet_address: Optional[str] = None
    bio: Optional[str] = None
    portfolio_link: Optional[str] = None
    github_link: Optional[str] = None
    skills: Optional[List[str]] = []
    rating: Optional[float] = 0.0
    completed_jobs_count: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name: str
    role: UserRole

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class WalletLink(BaseModel):
    wallet_address: str

class GoogleAuth(BaseModel):
    credential: str
    role: Optional[UserRole] = None

class GitHubAuth(BaseModel):
    code: str
    role: Optional[UserRole] = None



class Job(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id_onchain: Optional[int] = None
    title: str
    description: str
    budget_usdc: float
    required_skills: Optional[List[str]] = []
    client_id: str
    freelancer_id: Optional[str] = None
    has_team: bool = False
    status: JobStatus = JobStatus.CREATED
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    tx_hash: Optional[str] = None

class JobCreate(BaseModel):
    title: str
    description: str
    budget_usdc: float
    required_skills: Optional[List[str]] = []
    tx_hash: Optional[str] = None
    job_id_onchain: Optional[int] = None

class TeamMember(BaseModel):
    freelancer_id: str
    profit_percentage: float

class JobTeam(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    lead_freelancer_id: str
    members: List[TeamMember]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ProfileUpdate(BaseModel):
    name: Optional[str] = None
    bio: Optional[str] = None
    portfolio_link: Optional[str] = None
    github_link: Optional[str] = None
    skills: Optional[List[str]] = None

class RoleSwitch(BaseModel):
    new_role: UserRole

class TeamInvite(BaseModel):
    job_id: str
    freelancer_id: str
    profit_percentage: float

class RoleSwitch(BaseModel):
    new_role: UserRole

class JobAccept(BaseModel):
    tx_hash: Optional[str] = None

class JobComplete(BaseModel):
    tx_hash: Optional[str] = None

class Dispute(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    dispute_id_onchain: Optional[int] = None
    job_id: str
    raised_by: str
    reason: str
    status: str = "pending"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = None
    resolution: Optional[str] = None

class DisputeCreate(BaseModel):
    job_id: str
    reason: str
    tx_hash: Optional[str] = None

class DisputeResolve(BaseModel):
    client_percentage: int
    freelancer_percentage: int
    resolution: str
    tx_hash: Optional[str] = None

class ReleaseFunds(BaseModel):
    tx_hash: str

class ArbitratorSet(BaseModel):
    user_id: str

# Utility functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user_id: str, role: str) -> str:
    expiration = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': expiration
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user = await db.users.find_one({'id': payload['user_id']}, {'_id': 0, 'password_hash': 0})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def require_arbitrator(current_user: dict = Depends(get_current_user)):
    """Dependency to ensure only the designated arbitrator can access"""
    user_email = current_user['email']
    user_wallet = current_user.get('wallet_address', '').lower()
    
    # Allow access if user has arbitrator email OR arbitrator wallet
    is_arbitrator_email = user_email == ARBITRATOR_EMAIL
    is_arbitrator_wallet = user_wallet == ARBITRATOR_WALLET.lower()
    
    if not (is_arbitrator_email or is_arbitrator_wallet):
        raise HTTPException(status_code=403, detail="Access denied. Only arbitrator can access this resource.")
    
    return current_user


# Email helper function
async def send_verification_email(email: str, token: str):
    """Send verification email using SendGrid"""
    verification_link = f"{os.environ.get('FRONTEND_URL', 'http://localhost:3000')}?verify={token}"
    
    # Try to send real email if SendGrid is configured
    sendgrid_api_key = os.environ.get('SENDGRID_API_KEY')
    
    if sendgrid_api_key:
        try:
            import sendgrid
            from sendgrid.helpers.mail import Mail
            
            sg = sendgrid.SendGridAPIClient(api_key=sendgrid_api_key)
            
            message = Mail(
                from_email='noreply@cryptogig.com',
                to_emails=email,
                subject='Verify your CryptoGig account',
                html_content=f'''
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h1 style="color: #3b82f6;">Welcome to CryptoGig! 🚀</h1>
                    <p>Thank you for joining the future of freelancing with blockchain technology.</p>
                    <p>Please click the button below to verify your email address:</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="{verification_link}" 
                           style="background: linear-gradient(135deg, #3b82f6, #8b5cf6); 
                                  color: white; 
                                  padding: 15px 30px; 
                                  text-decoration: none; 
                                  border-radius: 8px; 
                                  font-weight: bold;">
                            Verify Email Address
                        </a>
                    </div>
                    <p>Or copy and paste this link in your browser:</p>
                    <p style="word-break: break-all; color: #6b7280;">{verification_link}</p>
                    <hr style="margin: 30px 0; border: none; border-top: 1px solid #e5e7eb;">
                    <p style="color: #6b7280; font-size: 14px;">
                        This link will expire in 24 hours. If you didn't create an account, please ignore this email.
                    </p>
                </div>
                '''
            )
            
            response = sg.send(message)
            print(f"✅ Email sent to {email} (Status: {response.status_code})")
            return True
            
        except Exception as e:
            print(f"❌ Failed to send email to {email}: {e}")
            # Fall back to console logging
    
    # Development fallback - log to console
    print("\n" + "="*60)
    print("📧 EMAIL VERIFICATION REQUIRED")
    print("="*60)
    print(f"📮 To: {email}")
    print(f"🔗 Verification Link:")
    print(f"   {verification_link}")
    print("="*60)
    
    logging.info(f"VERIFICATION LINK for {email}: {verification_link}")
    return True


# Auth endpoints
@api_router.post("/auth/register")
async def register(user_data: UserCreate):
    # Check if user exists
    existing = await db.users.find_one({'email': user_data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Check if this is the arbitrator email
    is_arbitrator = user_data.email == ARBITRATOR_EMAIL
    
    # Create user
    user_dict = user_data.model_dump()
    password = user_dict.pop('password')
    user_dict['password_hash'] = hash_password(password)
    user_dict['id'] = str(uuid.uuid4())
    user_dict['created_at'] = datetime.now(timezone.utc).isoformat()
    user_dict['wallet_address'] = None
    
    # Set role to arbitrator if it's the arbitrator email
    if is_arbitrator:
        user_dict['role'] = 'arbitrator'
        user_dict['active_role'] = 'arbitrator'
    else:
        user_dict['active_role'] = user_dict['role']
    
    user_dict['bio'] = None
    user_dict['portfolio_link'] = None
    user_dict['github_link'] = None
    user_dict['skills'] = []
    user_dict['rating'] = 0.0
    user_dict['completed_jobs_count'] = 0
    user_dict['email_verified'] = True  # Auto-verify all users
    
    await db.users.insert_one(user_dict)
    
    # Auto-login all users
    token = create_token(user_dict['id'], user_dict['role'])
    return {
        'access_token': token,
        'token_type': 'bearer',
        'user': {
            'id': user_dict['id'],
            'email': user_dict['email'],
            'name': user_dict['name'],
            'role': user_dict['role'],
            'active_role': user_dict['active_role']
        }
    }

@api_router.post("/auth/login")
async def login(credentials: UserLogin):
    user = await db.users.find_one({'email': credentials.email})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Handle both 'password' and 'password_hash' fields for backward compatibility
    password_field = user.get('password_hash') or user.get('password')
    if not password_field:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not verify_password(credentials.password, password_field):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token(user['id'], user.get('active_role', user['role']))
    
    return {
        'access_token': token,
        'token_type': 'bearer',
        'user': {
            'id': user['id'],
            'email': user['email'],
            'name': user['name'],
            'role': user['role'],
            'active_role': user.get('active_role', user['role']),
            'wallet_address': user.get('wallet_address')
        }
    }

@api_router.post("/auth/register-with-email")
async def register_with_email(user_data: UserCreate):
    # Check if user exists
    existing = await db.users.find_one({'email': user_data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create verification token
    verification_token = str(uuid.uuid4())
    
    # Create user (unverified)
    user_dict = user_data.model_dump()
    password = user_dict.pop('password')
    user_dict['password_hash'] = hash_password(password)
    user_dict['id'] = str(uuid.uuid4())
    user_dict['created_at'] = datetime.now(timezone.utc).isoformat()
    user_dict['wallet_address'] = None
    user_dict['active_role'] = user_dict['role']
    user_dict['bio'] = None
    user_dict['portfolio_link'] = None
    user_dict['github_link'] = None
    user_dict['skills'] = []
    user_dict['rating'] = 0.0
    user_dict['completed_jobs_count'] = 0
    user_dict['email_verified'] = False
    user_dict['verification_token'] = verification_token
    
    await db.users.insert_one(user_dict)
    
    # Send verification email
    await send_verification_email(user_dict['email'], verification_token)
    
    return {'success': True, 'message': 'Verification email sent'}

@api_router.get("/auth/verify-email")
async def verify_email(token: str):
    user = await db.users.find_one({'verification_token': token})
    if not user:
        raise HTTPException(status_code=400, detail="Invalid verification token")
    
    # Update user
    await db.users.update_one(
        {'id': user['id']},
        {'$set': {'email_verified': True}, '$unset': {'verification_token': ''}}
    )
    
    return {'success': True, 'message': 'Email verified successfully'}

@api_router.post("/auth/magic-link")
async def send_magic_link(data: dict):
    email = data.get('email')
    role = data.get('role', 'freelancer')
    
    if not email:
        raise HTTPException(status_code=400, detail="Email required")
    
    # Check if user exists
    user = await db.users.find_one({'email': email})
    
    if not user:
        # Create new user
        user_id = str(uuid.uuid4())
        magic_token = str(uuid.uuid4())
        
        user_dict = {
            'id': user_id,
            'email': email,
            'name': email.split('@')[0],
            'role': role,
            'active_role': role,
            'password_hash': '',
            'wallet_address': None,
            'bio': None,
            'portfolio_link': None,
            'github_link': None,
            'skills': [],
            'rating': 0.0,
            'completed_jobs_count': 0,
            'email_verified': True,
            'magic_token': magic_token,
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        
        await db.users.insert_one(user_dict)
    else:
        # Generate magic token for existing user
        magic_token = str(uuid.uuid4())
        await db.users.update_one(
            {'id': user['id']},
            {'$set': {'magic_token': magic_token}}
        )
        user_id = user['id']
    
    # Create login link
    login_link = f"{os.environ.get('FRONTEND_URL', 'http://localhost:3000')}?magic={magic_token}"
    
    # Log the magic link (in production, send via email)
    logging.info(f"=== MAGIC LINK ===")
    logging.info(f"Email: {email}")
    logging.info(f"Link: {login_link}")
    logging.info(f"==================")
    
    return {'success': True, 'message': 'Magic link sent to email'}

@api_router.get("/auth/magic-login")
async def magic_login(token: str):
    user = await db.users.find_one({'magic_token': token})
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired magic link")
    
    # Remove magic token
    await db.users.update_one(
        {'id': user['id']},
        {'$unset': {'magic_token': ''}}
    )
    
    # Create JWT token
    jwt_token = create_token(user['id'], user.get('active_role', user['role']))
    
    return {
        'token': jwt_token,
        'user': {
            'id': user['id'],
            'email': user['email'],
            'name': user['name'],
            'role': user.get('active_role', user['role']),
            'wallet_address': user.get('wallet_address')
        }
    }

@api_router.post("/auth/google")
async def google_auth(auth_data: GoogleAuth):
    try:
        # Verify the Google token
        idinfo = id_token.verify_oauth2_token(
            auth_data.credential,
            google_requests.Request(),
            os.environ.get('GOOGLE_CLIENT_ID')
        )
        
        # Check if user exists
        email = idinfo['email']
        user = await db.users.find_one({'email': email})
        
        if user:
            # Existing user - login
            token = create_token(user['id'], user.get('active_role', user['role']))
            return {
                'token': token,
                'user': {
                    'id': user['id'],
                    'email': user['email'],
                    'name': user['name'],
                    'role': user.get('active_role', user['role']),
                    'wallet_address': user.get('wallet_address')
                }
            }
        else:
            # New user - register
            if not auth_data.role:
                raise HTTPException(status_code=400, detail="Role required for new users")
            
            user_dict = {
                'id': str(uuid.uuid4()),
                'email': email,
                'name': idinfo.get('name', email.split('@')[0]),
                'role': auth_data.role,
                'active_role': auth_data.role,
                'password_hash': '',  # No password for Google auth
                'wallet_address': None,
                'bio': None,
                'portfolio_link': None,
                'github_link': None,
                'skills': [],
                'rating': 0.0,
                'completed_jobs_count': 0,
                'created_at': datetime.now(timezone.utc).isoformat()
            }
            
            await db.users.insert_one(user_dict)
            
            token = create_token(user_dict['id'], user_dict['role'])
            
            return {
                'token': token,
                'user': {
                    'id': user_dict['id'],
                    'email': user_dict['email'],
                    'name': user_dict['name'],
                    'role': user_dict['role']
                }
            }
    except ValueError as e:
        raise HTTPException(status_code=401, detail=f"Invalid Google token: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Authentication failed: {str(e)}")


@api_router.post("/auth/github")
async def github_auth(auth_data: GitHubAuth):
    try:
        import requests
        
        # Exchange code for access token
        client_id = os.environ.get('GITHUB_CLIENT_ID')
        client_secret = os.environ.get('GITHUB_CLIENT_SECRET')
        
        if not client_id or not client_secret:
            raise HTTPException(status_code=500, detail="GitHub OAuth not configured")
        
        # Get access token
        token_response = requests.post(
            'https://github.com/login/oauth/access_token',
            headers={'Accept': 'application/json'},
            data={
                'client_id': client_id,
                'client_secret': client_secret,
                'code': auth_data.code
            }
        )
        
        token_data = token_response.json()
        access_token = token_data.get('access_token')
        
        if not access_token:
            raise HTTPException(status_code=401, detail="Failed to get GitHub access token")
        
        # Get user info
        user_response = requests.get(
            'https://api.github.com/user',
            headers={
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json'
            }
        )
        
        user_info = user_response.json()
        
        # Get user email (might be private)
        email_response = requests.get(
            'https://api.github.com/user/emails',
            headers={
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json'
            }
        )
        
        emails = email_response.json()
        primary_email = next((e['email'] for e in emails if e['primary']), emails[0]['email'] if emails else None)
        
        if not primary_email:
            raise HTTPException(status_code=400, detail="No email found in GitHub account")
        
        # Check if user exists
        user = await db.users.find_one({'email': primary_email})
        
        if user:
            # Existing user - login
            token = create_token(user['id'], user.get('active_role', user['role']))
            return {
                'token': token,
                'user': {
                    'id': user['id'],
                    'email': user['email'],
                    'name': user['name'],
                    'role': user.get('active_role', user['role']),
                    'wallet_address': user.get('wallet_address')
                }
            }
        else:
            # New user - register
            if not auth_data.role:
                raise HTTPException(status_code=400, detail="Role required for new users")
            
            user_dict = {
                'id': str(uuid.uuid4()),
                'email': primary_email,
                'name': user_info.get('name') or user_info.get('login'),
                'role': auth_data.role,
                'active_role': auth_data.role,
                'password_hash': '',  # No password for GitHub auth
                'wallet_address': None,
                'bio': user_info.get('bio'),
                'portfolio_link': user_info.get('blog') or user_info.get('html_url'),
                'github_link': user_info.get('html_url'),
                'skills': [],
                'rating': 0.0,
                'completed_jobs_count': 0,
                'created_at': datetime.now(timezone.utc).isoformat()
            }
            
            await db.users.insert_one(user_dict)
            
            token = create_token(user_dict['id'], user_dict['role'])
            
            return {
                'token': token,
                'user': {
                    'id': user_dict['id'],
                    'email': user_dict['email'],
                    'name': user_dict['name'],
                    'role': user_dict['role']
                }
            }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"GitHub authentication failed: {str(e)}")

@api_router.get("/auth/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return current_user

@api_router.post("/auth/link-wallet")
async def link_wallet(wallet_data: WalletLink, current_user: dict = Depends(get_current_user)):
    await db.users.update_one(
        {'id': current_user['id']},
        {'$set': {'wallet_address': wallet_data.wallet_address.lower()}}
    )
    return {'success': True, 'wallet_address': wallet_data.wallet_address}

# Profile endpoints
@api_router.get("/profile/{user_id}")
async def get_profile(user_id: str):
    user = await db.users.find_one({'id': user_id}, {'_id': 0, 'password_hash': 0})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get completed jobs count
    if user['role'] == 'freelancer' or user.get('active_role') == 'freelancer':
        completed_jobs = await db.jobs.count_documents({
            'freelancer_id': user_id,
            'status': JobStatus.RESOLVED
        })
        user['completed_jobs_count'] = completed_jobs
    
    return user

@api_router.put("/profile")
async def update_profile(profile_data: ProfileUpdate, current_user: dict = Depends(get_current_user)):
    update_dict = {k: v for k, v in profile_data.model_dump().items() if v is not None}
    
    if update_dict:
        await db.users.update_one(
            {'id': current_user['id']},
            {'$set': update_dict}
        )
    
    return {'success': True, 'message': 'Profile updated'}

@api_router.get("/freelancers")
async def get_freelancers(skills: Optional[str] = None):
    query = {'$or': [{'role': 'freelancer'}, {'active_role': 'freelancer'}]}
    
    if skills:
        skill_list = [s.strip() for s in skills.split(',')]
        query['skills'] = {'$in': skill_list}
    
    freelancers = await db.users.find(query, {'_id': 0, 'password_hash': 0}).to_list(100)
    
    # Get ratings and completed jobs
    for freelancer in freelancers:
        completed = await db.jobs.count_documents({
            'freelancer_id': freelancer['id'],
            'status': JobStatus.RESOLVED
        })
        freelancer['completed_jobs_count'] = completed
    
    return freelancers

@api_router.post("/auth/switch-role")
async def switch_role(role_data: RoleSwitch, current_user: dict = Depends(get_current_user)):
    # Allow switching between client and freelancer
    if role_data.new_role == 'arbitrator':
        raise HTTPException(status_code=403, detail="Cannot switch to arbitrator role")
    
    # Validate role
    if role_data.new_role not in ['client', 'freelancer']:
        raise HTTPException(status_code=400, detail="Invalid role")
    
    # Update active role (users can have both client and freelancer capabilities)
    await db.users.update_one(
        {'id': current_user['id']},
        {'$set': {'active_role': role_data.new_role}}
    )
    
    # Get updated user data
    updated_user = await db.users.find_one({'id': current_user['id']}, {'_id': 0, 'password_hash': 0})
    
    return {
        'success': True, 
        'active_role': role_data.new_role,
        'user': {
            'id': updated_user['id'],
            'email': updated_user['email'],
            'name': updated_user['name'],
            'role': updated_user['role'],
            'active_role': role_data.new_role,
            'wallet_address': updated_user.get('wallet_address')
        }
    }


# Job endpoints
@api_router.post("/jobs", response_model=Job)
async def create_job(job_data: JobCreate, current_user: dict = Depends(get_current_user)):
    active_role = current_user.get('active_role', current_user['role'])
    if active_role != 'client':
        raise HTTPException(status_code=403, detail="Only clients can create jobs")
    
    job_dict = job_data.model_dump()
    job_dict['id'] = str(uuid.uuid4())
    job_dict['client_id'] = current_user['id']
    job_dict['freelancer_id'] = None
    job_dict['has_team'] = False
    job_dict['status'] = JobStatus.CREATED
    job_dict['created_at'] = datetime.now(timezone.utc).isoformat()
    job_dict['completed_at'] = None
    
    await db.jobs.insert_one(job_dict)
    
    if isinstance(job_dict['created_at'], str):
        job_dict['created_at'] = datetime.fromisoformat(job_dict['created_at'])
    
    return Job(**job_dict)

@api_router.get("/jobs", response_model=List[Job])
async def get_jobs(status: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    query = {}
    if status:
        query['status'] = status
    
    # Filter based on active role
    active_role = current_user.get('active_role', current_user['role'])
    if active_role == 'client':
        query['client_id'] = current_user['id']
    elif active_role == 'freelancer':
        # Show available jobs or their accepted jobs
        query = {'$or': [
            {'status': JobStatus.CREATED},
            {'freelancer_id': current_user['id']}
        ]}
    
    jobs = await db.jobs.find(query, {'_id': 0}).to_list(1000)
    
    for job in jobs:
        if isinstance(job.get('created_at'), str):
            job['created_at'] = datetime.fromisoformat(job['created_at'])
        if job.get('completed_at') and isinstance(job['completed_at'], str):
            job['completed_at'] = datetime.fromisoformat(job['completed_at'])
    
    return jobs

@api_router.get("/jobs/{job_id}", response_model=Job)
async def get_job(job_id: str, current_user: dict = Depends(get_current_user)):
    job = await db.jobs.find_one({'id': job_id}, {'_id': 0})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if isinstance(job.get('created_at'), str):
        job['created_at'] = datetime.fromisoformat(job['created_at'])
    if job.get('completed_at') and isinstance(job['completed_at'], str):
        job['completed_at'] = datetime.fromisoformat(job['completed_at'])
    
    return Job(**job)

@api_router.post("/jobs/{job_id}/accept")
async def accept_job(job_id: str, accept_data: JobAccept, current_user: dict = Depends(get_current_user)):
    active_role = current_user.get('active_role', current_user['role'])
    if active_role != 'freelancer':
        raise HTTPException(status_code=403, detail="Only freelancers can accept jobs")
    
    job = await db.jobs.find_one({'id': job_id})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if job['status'] != JobStatus.CREATED:
        raise HTTPException(status_code=400, detail="Job not available")
    
    await db.jobs.update_one(
        {'id': job_id},
        {'$set': {
            'freelancer_id': current_user['id'],
            'status': JobStatus.IN_PROGRESS
        }}
    )
    
    return {'success': True, 'message': 'Job accepted'}

@api_router.post("/jobs/{job_id}/complete")
async def complete_job(job_id: str, complete_data: JobComplete, current_user: dict = Depends(get_current_user)):
    job = await db.jobs.find_one({'id': job_id})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if job['freelancer_id'] != current_user['id']:
        raise HTTPException(status_code=403, detail="Only assigned freelancer can complete job")
    
    if job['status'] != JobStatus.IN_PROGRESS:
        raise HTTPException(status_code=400, detail="Job not in progress")
    
    await db.jobs.update_one(
        {'id': job_id},
        {'$set': {
            'status': JobStatus.COMPLETED,
            'completed_at': datetime.now(timezone.utc).isoformat()
        }}
    )
    
    return {'success': True, 'message': 'Job marked as completed'}

# Dispute endpoints
@api_router.post("/disputes")
async def create_dispute(dispute_data: DisputeCreate, current_user: dict = Depends(get_current_user)):
    job = await db.jobs.find_one({'id': dispute_data.job_id})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # Check if user is part of the job
    if current_user['id'] not in [job['client_id'], job.get('freelancer_id')]:
        raise HTTPException(status_code=403, detail="Only job participants can raise disputes")
    
    # Check if already disputed
    existing = await db.disputes.find_one({'job_id': dispute_data.job_id, 'status': 'pending'})
    if existing:
        raise HTTPException(status_code=400, detail="Dispute already exists for this job")
    
    dispute_dict = dispute_data.model_dump()
    dispute_dict['id'] = str(uuid.uuid4())
    dispute_dict['raised_by'] = current_user['id']
    dispute_dict['status'] = 'pending'
    dispute_dict['created_at'] = datetime.now(timezone.utc).isoformat()
    dispute_dict['resolved_at'] = None
    dispute_dict['resolution'] = None
    
    await db.disputes.insert_one(dispute_dict)
    await db.jobs.update_one({'id': dispute_data.job_id}, {'$set': {'status': JobStatus.DISPUTED}})
    
    return {'success': True, 'dispute_id': dispute_dict['id']}

# Team collaboration endpoints
@api_router.post("/jobs/{job_id}/team/invite")
async def invite_to_team(job_id: str, invite_data: TeamInvite, current_user: dict = Depends(get_current_user)):
    job = await db.jobs.find_one({'id': job_id})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # Check if current user is the lead freelancer
    if job['freelancer_id'] != current_user['id']:
        raise HTTPException(status_code=403, detail="Only lead freelancer can invite team members")
    
    # Check if team already exists
    team = await db.job_teams.find_one({'job_id': job_id})
    
    if not team:
        # Create new team
        team = {
            'id': str(uuid.uuid4()),
            'job_id': job_id,
            'lead_freelancer_id': current_user['id'],
            'members': [],
            'created_at': datetime.now(timezone.utc).isoformat()
        }
    
    # Add member
    team['members'].append({
        'freelancer_id': invite_data.freelancer_id,
        'profit_percentage': invite_data.profit_percentage,
        'status': 'pending'
    })
    
    # Validate total percentage doesn't exceed 100
    total_percentage = sum(m['profit_percentage'] for m in team['members'])
    if total_percentage > 100:
        raise HTTPException(status_code=400, detail="Total profit percentage cannot exceed 100%")
    
    await db.job_teams.update_one(
        {'job_id': job_id},
        {'$set': team},
        upsert=True
    )
    
    # Update job to mark it has a team
    await db.jobs.update_one({'id': job_id}, {'$set': {'has_team': True}})
    
    return {'success': True, 'message': 'Team member invited'}

@api_router.get("/jobs/{job_id}/team")
async def get_job_team(job_id: str, current_user: dict = Depends(get_current_user)):
    team = await db.job_teams.find_one({'job_id': job_id}, {'_id': 0})
    if not team:
        return {'has_team': False, 'members': []}
    
    # Get member details
    member_ids = [m['freelancer_id'] for m in team['members']]
    members_data = await db.users.find(
        {'id': {'$in': member_ids}},
        {'_id': 0, 'id': 1, 'name': 1, 'skills': 1, 'rating': 1}
    ).to_list(100)
    
    # Merge member data with profit percentages
    for member in team['members']:
        user_data = next((u for u in members_data if u['id'] == member['freelancer_id']), None)
        if user_data:
            member.update(user_data)
    
    return team

@api_router.post("/jobs/{job_id}/team/accept")
async def accept_team_invite(job_id: str, current_user: dict = Depends(get_current_user)):
    team = await db.job_teams.find_one({'job_id': job_id})
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")
    
    # Find member invitation
    member_found = False
    for member in team['members']:
        if member['freelancer_id'] == current_user['id']:
            member['status'] = 'accepted'
            member_found = True
            break
    
    if not member_found:
        raise HTTPException(status_code=404, detail="No invitation found")
    
    await db.job_teams.update_one(
        {'job_id': job_id},
        {'$set': {'members': team['members']}}
    )
    
    return {'success': True, 'message': 'Team invitation accepted'}

@api_router.get("/team/invitations")
async def get_team_invitations(current_user: dict = Depends(get_current_user)):
    teams = await db.job_teams.find({
        'members.freelancer_id': current_user['id'],
        'members.status': 'pending'
    }, {'_id': 0}).to_list(100)
    
    # Get job details for each team
    for team in teams:
        job = await db.jobs.find_one({'id': team['job_id']}, {'_id': 0})
        team['job'] = job
    
    return teams


@api_router.get("/disputes")
async def get_disputes(current_user: dict = Depends(get_current_user)):
    active_role = current_user.get('active_role', current_user['role'])
    if active_role != 'arbitrator':
        # Users can only see their own disputes
        jobs = await db.jobs.find({
            '$or': [
                {'client_id': current_user['id']},
                {'freelancer_id': current_user['id']}
            ]
        }, {'_id': 0, 'id': 1}).to_list(1000)
        job_ids = [job['id'] for job in jobs]
        disputes = await db.disputes.find({'job_id': {'$in': job_ids}}, {'_id': 0}).to_list(1000)
    else:
        disputes = await db.disputes.find({}, {'_id': 0}).to_list(1000)
    
    for dispute in disputes:
        if isinstance(dispute.get('created_at'), str):
            dispute['created_at'] = datetime.fromisoformat(dispute['created_at'])
        if dispute.get('resolved_at') and isinstance(dispute['resolved_at'], str):
            dispute['resolved_at'] = datetime.fromisoformat(dispute['resolved_at'])
    
    return disputes

@api_router.post("/disputes/{dispute_id}/resolve")
async def resolve_dispute(dispute_id: str, resolution_data: DisputeResolve, current_user: dict = Depends(require_arbitrator)):
    dispute = await db.disputes.find_one({'id': dispute_id})
    if not dispute:
        raise HTTPException(status_code=404, detail="Dispute not found")
    
    if dispute['status'] != 'pending':
        raise HTTPException(status_code=400, detail="Dispute already resolved")
    
    await db.disputes.update_one(
        {'id': dispute_id},
        {'$set': {
            'status': 'resolved',
            'resolution': resolution_data.resolution,
            'resolved_at': datetime.now(timezone.utc).isoformat()
        }}
    )
    
    await db.jobs.update_one({'id': dispute['job_id']}, {'$set': {'status': JobStatus.RESOLVED}})
    
    return {'success': True, 'message': 'Dispute resolved'}

# Arbitrator endpoints
@api_router.post("/jobs/{job_id}/release")
async def release_funds(job_id: str, release_data: ReleaseFunds, current_user: dict = Depends(require_arbitrator)):
    active_role = current_user.get('active_role', current_user['role'])
    if active_role != 'arbitrator':
        raise HTTPException(status_code=403, detail="Only arbitrator can release funds")
    
    job = await db.jobs.find_one({'id': job_id})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if job['status'] != JobStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Job not completed")
    
    await db.jobs.update_one({'id': job_id}, {'$set': {'status': JobStatus.RESOLVED}})
    
    return {'success': True, 'message': 'Funds released'}

@api_router.get("/admin/arbitrator")
async def get_arbitrator():
    arbitrator = await db.settings.find_one({'key': 'arbitrator_id'}, {'_id': 0})
    if not arbitrator:
        return {'arbitrator_id': None}
    return arbitrator

@api_router.post("/admin/arbitrator")
async def set_arbitrator(arbitrator_data: ArbitratorSet, current_user: dict = Depends(get_current_user)):
    # Only existing arbitrator or first setup can set new arbitrator
    existing = await db.settings.find_one({'key': 'arbitrator_id'})
    
    active_role = current_user.get('active_role', current_user['role'])
    if existing and existing.get('value') != current_user['id']:
        if active_role != 'arbitrator':
            raise HTTPException(status_code=403, detail="Only current arbitrator can change arbitrator")
    
    # Update user role
    await db.users.update_one(
        {'id': arbitrator_data.user_id},
        {'$set': {'role': 'arbitrator'}}
    )
    
    # Set in settings
    await db.settings.update_one(
        {'key': 'arbitrator_id'},
        {'$set': {'value': arbitrator_data.user_id}},
        upsert=True
    )
    
    return {'success': True, 'arbitrator_id': arbitrator_data.user_id}

@api_router.get("/stats")
async def get_stats(current_user: dict = Depends(get_current_user)):
    active_role = current_user.get('active_role', current_user['role'])
    if active_role == 'arbitrator':
        total_jobs = await db.jobs.count_documents({})
        pending_disputes = await db.disputes.count_documents({'status': 'pending'})
        completed_jobs = await db.jobs.count_documents({'status': JobStatus.RESOLVED})
        
        return {
            'total_jobs': total_jobs,
            'pending_disputes': pending_disputes,
            'completed_jobs': completed_jobs
        }
    elif active_role == 'client':
        my_jobs = await db.jobs.count_documents({'client_id': current_user['id']})
        active_jobs = await db.jobs.count_documents({
            'client_id': current_user['id'],
            'status': {'$in': [JobStatus.CREATED, JobStatus.IN_PROGRESS]}
        })
        return {'total_jobs': my_jobs, 'active_jobs': active_jobs}
    else:  # freelancer
        my_jobs = await db.jobs.count_documents({'freelancer_id': current_user['id']})
        completed = await db.jobs.count_documents({
            'freelancer_id': current_user['id'],
            'status': JobStatus.RESOLVED
        })
        return {'total_jobs': my_jobs, 'completed_jobs': completed}

@api_router.get("/")
async def root():
    return {
        "message": "CryptoGig API", 
        "version": "2.0.0-no-email-verification",
        "features": ["instant_registration", "mongodb_integrated"],
        "deployed": datetime.now(timezone.utc).isoformat()
    }

# Community/Channel Models
class Channel(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    skill: str
    creator_id: str
    members: List[str] = []
    member_count: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    description: Optional[str] = None

class ChannelCreate(BaseModel):
    name: str
    skill: str
    description: Optional[str] = None

class Message(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    channel_id: str
    user_id: str
    user_name: str
    content: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class MessageCreate(BaseModel):
    content: str

class VoteToKick(BaseModel):
    target_user_id: str
    reason: str

# Channel/Community Endpoints
@api_router.post("/channels")
async def create_channel(channel_data: ChannelCreate, current_user: dict = Depends(get_current_user)):
    # Check if channel with same skill already exists
    existing = await db.channels.find_one({'skill': channel_data.skill.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Channel for this skill already exists")
    
    channel_dict = channel_data.model_dump()
    channel_dict['id'] = str(uuid.uuid4())
    channel_dict['creator_id'] = current_user['id']
    channel_dict['members'] = [current_user['id']]
    channel_dict['member_count'] = 1
    channel_dict['skill'] = channel_data.skill.lower()
    channel_dict['created_at'] = datetime.now(timezone.utc).isoformat()
    
    await db.channels.insert_one(channel_dict)
    
    return {'success': True, 'channel_id': channel_dict['id']}

@api_router.get("/channels")
async def get_channels(skill: Optional[str] = None):
    query = {}
    if skill:
        query['skill'] = skill.lower()
    
    channels = await db.channels.find(query, {'_id': 0}).to_list(100)
    
    for channel in channels:
        if isinstance(channel.get('created_at'), str):
            channel['created_at'] = datetime.fromisoformat(channel['created_at'])
    
    return channels

@api_router.post("/channels/{channel_id}/join")
async def join_channel(channel_id: str, current_user: dict = Depends(get_current_user)):
    channel = await db.channels.find_one({'id': channel_id})
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")
    
    if current_user['id'] in channel['members']:
        raise HTTPException(status_code=400, detail="Already a member")
    
    await db.channels.update_one(
        {'id': channel_id},
        {
            '$push': {'members': current_user['id']},
            '$inc': {'member_count': 1}
        }
    )
    
    return {'success': True, 'message': 'Joined channel'}

@api_router.post("/channels/{channel_id}/leave")
async def leave_channel(channel_id: str, current_user: dict = Depends(get_current_user)):
    channel = await db.channels.find_one({'id': channel_id})
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")
    
    if current_user['id'] not in channel['members']:
        raise HTTPException(status_code=400, detail="Not a member")
    
    # Creator cannot leave their own channel
    if current_user['id'] == channel['creator_id']:
        raise HTTPException(status_code=400, detail="Creator cannot leave channel")
    
    await db.channels.update_one(
        {'id': channel_id},
        {
            '$pull': {'members': current_user['id']},
            '$inc': {'member_count': -1}
        }
    )
    
    return {'success': True, 'message': 'Left channel'}

@api_router.get("/channels/{channel_id}/messages")
async def get_messages(channel_id: str, current_user: dict = Depends(get_current_user)):
    # Check if user is a member
    channel = await db.channels.find_one({'id': channel_id})
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")
    
    if current_user['id'] not in channel['members']:
        raise HTTPException(status_code=403, detail="Must be a member to view messages")
    
    messages = await db.messages.find({'channel_id': channel_id}, {'_id': 0}).sort('created_at', 1).to_list(1000)
    
    for msg in messages:
        if isinstance(msg.get('created_at'), str):
            msg['created_at'] = datetime.fromisoformat(msg['created_at'])
    
    return messages

@api_router.post("/channels/{channel_id}/messages")
async def send_message(channel_id: str, message_data: MessageCreate, current_user: dict = Depends(get_current_user)):
    # Check if user is a member
    channel = await db.channels.find_one({'id': channel_id})
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")
    
    if current_user['id'] not in channel['members']:
        raise HTTPException(status_code=403, detail="Must be a member to send messages")
    
    message_dict = message_data.model_dump()
    message_dict['id'] = str(uuid.uuid4())
    message_dict['channel_id'] = channel_id
    message_dict['user_id'] = current_user['id']
    message_dict['user_name'] = current_user['name']
    message_dict['created_at'] = datetime.now(timezone.utc).isoformat()
    
    await db.messages.insert_one(message_dict)
    
    return {'success': True, 'message_id': message_dict['id']}

@api_router.post("/channels/{channel_id}/vote-kick")
async def vote_to_kick(channel_id: str, vote_data: VoteToKick, current_user: dict = Depends(get_current_user)):
    channel = await db.channels.find_one({'id': channel_id})
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")
    
    if current_user['id'] not in channel['members']:
        raise HTTPException(status_code=403, detail="Must be a member to vote")
    
    if vote_data.target_user_id not in channel['members']:
        raise HTTPException(status_code=400, detail="Target user not in channel")
    
    if vote_data.target_user_id == channel['creator_id']:
        raise HTTPException(status_code=400, detail="Cannot kick channel creator")
    
    # Check if vote already exists
    existing_vote = await db.kick_votes.find_one({
        'channel_id': channel_id,
        'target_user_id': vote_data.target_user_id,
        'voter_id': current_user['id'],
        'status': 'active'
    })
    
    if existing_vote:
        raise HTTPException(status_code=400, detail="You already voted to kick this user")
    
    # Create vote
    vote_dict = {
        'id': str(uuid.uuid4()),
        'channel_id': channel_id,
        'target_user_id': vote_data.target_user_id,
        'voter_id': current_user['id'],
        'reason': vote_data.reason,
        'status': 'active',
        'created_at': datetime.now(timezone.utc).isoformat()
    }
    
    await db.kick_votes.insert_one(vote_dict)
    
    # Count total votes for this user
    total_votes = await db.kick_votes.count_documents({
        'channel_id': channel_id,
        'target_user_id': vote_data.target_user_id,
        'status': 'active'
    })
    
    # Need majority (> 50%) to kick
    member_count = channel['member_count']
    required_votes = (member_count // 2) + 1
    
    if total_votes >= required_votes:
        # Kick user
        await db.channels.update_one(
            {'id': channel_id},
            {
                '$pull': {'members': vote_data.target_user_id},
                '$inc': {'member_count': -1}
            }
        )
        
        # Mark votes as executed
        await db.kick_votes.update_many(
            {
                'channel_id': channel_id,
                'target_user_id': vote_data.target_user_id,
                'status': 'active'
            },
            {'$set': {'status': 'executed'}}
        )
        
        return {'success': True, 'message': 'User kicked from channel', 'kicked': True}
    
    return {'success': True, 'message': f'Vote recorded. {total_votes}/{required_votes} votes', 'kicked': False}

@api_router.get("/channels/{channel_id}/members")
async def get_channel_members(channel_id: str, current_user: dict = Depends(get_current_user)):
    channel = await db.channels.find_one({'id': channel_id})
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")
    
    if current_user['id'] not in channel['members']:
        raise HTTPException(status_code=403, detail="Must be a member to view members")
    
    # Get member details
    member_details = []
    for member_id in channel['members']:
        user = await db.users.find_one({'id': member_id}, {'_id': 0, 'password_hash': 0, 'verification_token': 0})
        if user:
            member_details.append({
                'id': user['id'],
                'name': user['name'],
                'email': user['email'],
                'role': user.get('role', 'freelancer'),
                'is_creator': user['id'] == channel['creator_id']
            })
    
    return member_details

@api_router.get("/my-channels")
async def get_my_channels(current_user: dict = Depends(get_current_user)):
    channels = await db.channels.find({'members': current_user['id']}, {'_id': 0}).to_list(100)
    
    for channel in channels:
        if isinstance(channel.get('created_at'), str):
            channel['created_at'] = datetime.fromisoformat(channel['created_at'])
    
    return channels

# Health check endpoint for Railway
@api_router.get("/health")
async def health_check():
    """Health check endpoint for Railway deployment"""
    try:
        # Test database connection
        await db.command("ping")
        return {
            "status": "healthy",
            "version": "2.0.0-FIXED-NO-EMAIL-VERIFICATION",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "database": "connected",
            "service": "cryptogig-backend",
            "features": ["instant_registration", "mongodb_integrated", "no_email_verification"],
            "git_commit": "force-deploy-v2"
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unhealthy")

# Add CORS middleware BEFORE including router
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include router
app.include_router(api_router)

# Startup message
logger.info("=" * 50)
logger.info("CryptoGig Backend Server Starting...")
logger.info(f"MongoDB Database: {os.environ.get('DB_NAME', 'cryptogig_db')}")
logger.info(f"Arbitrator Wallet: {ARBITRATOR_WALLET}")
logger.info("=" * 50)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()# Force rebuild Sat Nov  8 18:51:27 IST 2025
