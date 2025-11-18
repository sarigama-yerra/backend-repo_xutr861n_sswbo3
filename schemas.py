"""
Database Schemas for NODO MVP

Each Pydantic model conceptually maps to a MongoDB collection (lowercased name).
Collections used:
- users
- sessions
- profiles
- opportunities
- proposals
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal
from datetime import datetime


class UserRegister(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: Literal["developer", "contractor"]


class UserPublic(BaseModel):
    id: str = Field(..., description="User ID")
    name: str
    email: EmailStr
    role: Literal["developer", "contractor"]
    verified: bool = False


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class SessionToken(BaseModel):
    token: str


class ContractorProfileIn(BaseModel):
    logo_url: Optional[str] = None
    company_name: str
    categories: List[str] = []
    experience: Optional[str] = None
    past_projects: List[str] = []
    contact_email: Optional[EmailStr] = None
    contact_phone: Optional[str] = None
    location: Optional[str] = None


class ContractorProfileOut(ContractorProfileIn):
    id: str
    user_id: str
    rating: Optional[float] = 0.0
    ratings_count: int = 0


class OpportunityCreate(BaseModel):
    title: str
    category: str
    description: str
    files: List[str] = []  # store uploaded file URLs or filenames
    deadline: Optional[datetime] = None
    budget: Optional[float] = None
    location: Optional[str] = None


class OpportunityOut(OpportunityCreate):
    id: str
    developer_id: str
    created_at: datetime


class ProposalCreate(BaseModel):
    amount: Optional[float] = None
    message: str
    attachments: List[str] = []
    timeline_weeks: Optional[int] = None


class ProposalOut(ProposalCreate):
    id: str
    opportunity_id: str
    contractor_id: str
    status: Literal["submitted", "viewed", "selected"] = "submitted"
    created_at: datetime
