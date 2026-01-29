from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr, ConfigDict
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import jwt
from passlib.context import CryptContext

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'pixzent-super-secret-key-2026-change-in-production')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Security
security = HTTPBearer()

# Create the main app without a prefix
app = FastAPI(title="PixZent API", version="1.0.0")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# ============ MODELS ============

class AdminUser(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    password_hash: str
    name: str = "Admin"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AdminUserCreate(BaseModel):
    email: EmailStr
    password: str
    name: str = "Admin"

class AdminLoginRequest(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class AuditSubmission(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    full_name: str
    business_name: Optional[str] = None
    website_url: str
    email: EmailStr
    phone: str
    location: Optional[str] = None
    industry: str
    challenge: Optional[str] = None
    status: str = "New"  # New, In Progress, Completed
    notes: str = ""
    audit_sent: bool = False
    audit_sent_date: Optional[datetime] = None
    # Tracking fields
    source: str = "Website"  # Website, Chatbot, Direct, etc.
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    referrer: Optional[str] = None
    utm_source: Optional[str] = None
    utm_medium: Optional[str] = None
    utm_campaign: Optional[str] = None
    utm_term: Optional[str] = None
    utm_content: Optional[str] = None
    page_url: Optional[str] = None
    geo_country: Optional[str] = None
    geo_city: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AuditSubmissionCreate(BaseModel):
    full_name: str
    business_name: Optional[str] = None
    website_url: str
    email: EmailStr
    phone: str
    location: Optional[str] = None
    industry: str
    challenge: Optional[str] = None
    # Tracking fields
    source: Optional[str] = "Website"
    utm_source: Optional[str] = None
    utm_medium: Optional[str] = None
    utm_campaign: Optional[str] = None
    utm_term: Optional[str] = None
    utm_content: Optional[str] = None
    page_url: Optional[str] = None
    referrer: Optional[str] = None

class AuditSubmissionUpdate(BaseModel):
    status: Optional[str] = None
    notes: Optional[str] = None
    audit_sent: Optional[bool] = None
    audit_sent_date: Optional[datetime] = None

class StatusCheck(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    client_name: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class StatusCheckCreate(BaseModel):
    client_name: str

# ============ HELPER FUNCTIONS ============

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token"
            )
        return email
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token"
        )

def serialize_datetime(obj):
    """Convert datetime objects to ISO format strings for MongoDB storage"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj

def deserialize_datetime(date_str):
    """Convert ISO format strings back to datetime objects"""
    if isinstance(date_str, str):
        try:
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except:
            return date_str
    return date_str

def get_client_ip(request: Request) -> str:
    """Extract client IP from request"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "Unknown"

# ============ PUBLIC ROUTES ============

@api_router.get("/")
async def root():
    return {"message": "PixZent API is running", "version": "1.0.0"}

@api_router.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}

# ============ AUDIT SUBMISSION ROUTES (Public) ============

@api_router.post("/audit-submissions", response_model=AuditSubmission)
async def create_audit_submission(submission: AuditSubmissionCreate, request: Request):
    """Create a new audit submission from the landing page form"""
    try:
        # Get tracking info from request
        client_ip = get_client_ip(request)
        user_agent = request.headers.get("User-Agent", "Unknown")
        referrer = request.headers.get("Referer", submission.referrer)
        
        submission_data = submission.model_dump()
        submission_data['ip_address'] = client_ip
        submission_data['user_agent'] = user_agent
        submission_data['referrer'] = referrer
        
        # Set defaults for optional fields
        if not submission_data.get('business_name'):
            submission_data['business_name'] = submission_data['full_name']
        if not submission_data.get('location'):
            submission_data['location'] = 'Not specified'
        if not submission_data.get('challenge'):
            submission_data['challenge'] = 'Audit request'
        if not submission_data.get('source'):
            submission_data['source'] = 'Website'
        
        submission_obj = AuditSubmission(**submission_data)
        
        # Convert to dict for MongoDB
        doc = submission_obj.model_dump()
        doc['created_at'] = serialize_datetime(doc['created_at'])
        doc['updated_at'] = serialize_datetime(doc['updated_at'])
        if doc.get('audit_sent_date'):
            doc['audit_sent_date'] = serialize_datetime(doc['audit_sent_date'])
        
        await db.audit_submissions.insert_one(doc)
        
        logger.info(f"New audit submission created: {submission.email} from {submission.source} (IP: {client_ip})")
        return submission_obj
    except Exception as e:
        logger.error(f"Error creating audit submission: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create audit submission: {str(e)}")

# ============ AUTH ROUTES ============

@api_router.post("/auth/login", response_model=Token)
async def login(login_request: AdminLoginRequest):
    """Login for admin users"""
    # Find user by email
    user_doc = await db.admin_users.find_one({"email": login_request.email})
    
    if not user_doc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    if not verify_password(login_request.password, user_doc['password_hash']):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    # Create access token
    access_token = create_access_token(data={"sub": user_doc['email']})
    
    logger.info(f"Admin login successful: {login_request.email}")
    
    return Token(
        access_token=access_token,
        expires_in=ACCESS_TOKEN_EXPIRE_HOURS * 3600
    )

@api_router.get("/auth/verify")
async def verify_auth(email: str = Depends(verify_token)):
    """Verify if the current token is valid"""
    user_doc = await db.admin_users.find_one({"email": email})
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found")
    return {"valid": True, "email": email, "name": user_doc.get('name', 'Admin')}

# ============ ADMIN ROUTES (Protected) ============

@api_router.get("/admin/submissions", response_model=List[AuditSubmission])
async def get_all_submissions(email: str = Depends(verify_token)):
    """Get all audit submissions (admin only)"""
    submissions = await db.audit_submissions.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    
    # Deserialize dates
    for sub in submissions:
        sub['created_at'] = deserialize_datetime(sub.get('created_at'))
        sub['updated_at'] = deserialize_datetime(sub.get('updated_at'))
        if sub.get('audit_sent_date'):
            sub['audit_sent_date'] = deserialize_datetime(sub['audit_sent_date'])
    
    return submissions

@api_router.get("/admin/submissions/{submission_id}", response_model=AuditSubmission)
async def get_submission(submission_id: str, email: str = Depends(verify_token)):
    """Get a single audit submission by ID (admin only)"""
    submission = await db.audit_submissions.find_one({"id": submission_id}, {"_id": 0})
    
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")
    
    # Deserialize dates
    submission['created_at'] = deserialize_datetime(submission.get('created_at'))
    submission['updated_at'] = deserialize_datetime(submission.get('updated_at'))
    if submission.get('audit_sent_date'):
        submission['audit_sent_date'] = deserialize_datetime(submission['audit_sent_date'])
    
    return submission

@api_router.patch("/admin/submissions/{submission_id}", response_model=AuditSubmission)
async def update_submission(
    submission_id: str,
    update_data: AuditSubmissionUpdate,
    email: str = Depends(verify_token)
):
    """Update an audit submission (admin only)"""
    # Get current submission
    submission = await db.audit_submissions.find_one({"id": submission_id})
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")
    
    # Build update document
    update_dict = {k: v for k, v in update_data.model_dump().items() if v is not None}
    update_dict['updated_at'] = datetime.now(timezone.utc).isoformat()
    
    if 'audit_sent_date' in update_dict and update_dict['audit_sent_date']:
        update_dict['audit_sent_date'] = serialize_datetime(update_dict['audit_sent_date'])
    
    # Update in database
    await db.audit_submissions.update_one(
        {"id": submission_id},
        {"$set": update_dict}
    )
    
    # Get updated submission
    updated = await db.audit_submissions.find_one({"id": submission_id}, {"_id": 0})
    updated['created_at'] = deserialize_datetime(updated.get('created_at'))
    updated['updated_at'] = deserialize_datetime(updated.get('updated_at'))
    if updated.get('audit_sent_date'):
        updated['audit_sent_date'] = deserialize_datetime(updated['audit_sent_date'])
    
    logger.info(f"Submission updated: {submission_id} by {email}")
    return updated

@api_router.delete("/admin/submissions/{submission_id}")
async def delete_submission(submission_id: str, email: str = Depends(verify_token)):
    """Delete an audit submission (admin only)"""
    result = await db.audit_submissions.delete_one({"id": submission_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Submission not found")
    
    logger.info(f"Submission deleted: {submission_id} by {email}")
    return {"message": "Submission deleted successfully"}

@api_router.get("/admin/stats")
async def get_admin_stats(email: str = Depends(verify_token)):
    """Get dashboard statistics (admin only)"""
    total = await db.audit_submissions.count_documents({})
    new_count = await db.audit_submissions.count_documents({"status": "New"})
    in_progress = await db.audit_submissions.count_documents({"status": "In Progress"})
    completed = await db.audit_submissions.count_documents({"status": "Completed"})
    
    # Source breakdown
    website_count = await db.audit_submissions.count_documents({"source": "Website"})
    chatbot_count = await db.audit_submissions.count_documents({"source": "Chatbot"})
    
    return {
        "total": total,
        "new": new_count,
        "in_progress": in_progress,
        "completed": completed,
        "by_source": {
            "website": website_count,
            "chatbot": chatbot_count
        }
    }

# ============ STATUS CHECK ROUTES ============

@api_router.post("/status", response_model=StatusCheck)
async def create_status_check(input: StatusCheckCreate):
    status_dict = input.model_dump()
    status_obj = StatusCheck(**status_dict)
    
    doc = status_obj.model_dump()
    doc['timestamp'] = doc['timestamp'].isoformat()
    
    await db.status_checks.insert_one(doc)
    return status_obj

@api_router.get("/status", response_model=List[StatusCheck])
async def get_status_checks():
    status_checks = await db.status_checks.find({}, {"_id": 0}).to_list(1000)
    
    for check in status_checks:
        if isinstance(check['timestamp'], str):
            check['timestamp'] = datetime.fromisoformat(check['timestamp'])
    
    return status_checks

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============ STARTUP EVENT - Create default admin user ============

@app.on_event("startup")
async def startup_event():
    """Create default admin user if not exists"""
    default_email = "dmb@pixzent.com"
    default_password = "uaepixzent@#2026@$"
    
    # Check if admin user exists
    existing_user = await db.admin_users.find_one({"email": default_email})
    
    if not existing_user:
        admin_user = {
            "id": str(uuid.uuid4()),
            "email": default_email,
            "password_hash": get_password_hash(default_password),
            "name": "PixZent Admin",
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await db.admin_users.insert_one(admin_user)
        logger.info(f"Default admin user created: {default_email}")
    else:
        logger.info(f"Admin user already exists: {default_email}")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
