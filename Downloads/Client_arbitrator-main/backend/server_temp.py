from fastapi import FastAPI, APIRouter, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import os
from datetime import datetime, timezone

# Create the main app
app = FastAPI()
api_router = APIRouter(prefix="/api")

# Health check endpoint
@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": "not_configured",
        "service": "cryptogig-backend",
        "message": "MongoDB not configured yet"
    }

# Temporary registration endpoint
@api_router.post("/auth/register")
async def register():
    """Temporary registration endpoint"""
    raise HTTPException(
        status_code=503, 
        detail="Database not configured. Please set up MongoDB Atlas first."
    )

# Temporary login endpoint
@api_router.post("/auth/login")
async def login():
    """Temporary login endpoint"""
    raise HTTPException(
        status_code=503, 
        detail="Database not configured. Please set up MongoDB Atlas first."
    )

# Include router
app.include_router(api_router)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],  # Temporary - allow all origins
    allow_methods=["*"],
    allow_headers=["*"],
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)