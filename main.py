import os
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr
import hashlib
import secrets
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import (
    UserRegister,
    UserPublic,
    LoginRequest,
    SessionToken,
    ContractorProfileIn,
    ContractorProfileOut,
    OpportunityCreate,
    OpportunityOut,
    ProposalCreate,
    ProposalOut,
)

app = FastAPI(title="NODO API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Utils

def oid(obj: Any) -> str:
    return str(obj) if isinstance(obj, ObjectId) else str(obj)


def hash_password(password: str, salt: Optional[str] = None) -> Dict[str, str]:
    salt = salt or secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return {"salt": salt, "hash": h}


def verify_password(password: str, salt: str, hash_value: str) -> bool:
    return hashlib.sha256((salt + password).encode()).hexdigest() == hash_value


def generate_token() -> str:
    return secrets.token_urlsafe(32)


# Auth dependency
class AuthedUser(BaseModel):
    id: str
    email: EmailStr
    name: str
    role: str


def get_current_user(authorization: Optional[str] = None) -> AuthedUser:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    # Expect: Bearer <token>
    parts = authorization.split()
    token = parts[-1]
    session = db.sessions.find_one({"token": token})
    if not session:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.users.find_one({"_id": session["user_id"]})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return AuthedUser(id=oid(user["_id"]), email=user["email"], name=user["name"], role=user["role"]) 


# Routes
@app.get("/")
def root():
    return {"message": "NODO API is running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()[:10]
            response["database"] = "✅ Connected & Working"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:80]}"
    return response


# Authentication
@app.post("/auth/register")
def register(payload: UserRegister):
    # Check existing
    if db.users.find_one({"email": payload.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    pw = hash_password(payload.password)
    verification_code = secrets.token_hex(3)  # 6 hex chars
    doc = {
        "name": payload.name,
        "email": payload.email,
        "role": payload.role,
        "password_salt": pw["salt"],
        "password_hash": pw["hash"],
        "verified": False,
        "verification_code": verification_code,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db.users.insert_one(doc)
    # In a real app, send email here. For MVP, return code so user can verify.
    return {"message": "Registered. Verify your email with the provided code.", "verification_code": verification_code}


class VerifyRequest(BaseModel):
    email: EmailStr
    code: str


@app.post("/auth/verify")
def verify_email(payload: VerifyRequest):
    user = db.users.find_one({"email": payload.email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.get("verified"):
        return {"message": "Already verified"}
    if payload.code != user.get("verification_code"):
        raise HTTPException(status_code=400, detail="Invalid verification code")
    db.users.update_one({"_id": user["_id"]}, {"$set": {"verified": True}, "$unset": {"verification_code": ""}})
    return {"message": "Email verified"}


@app.post("/auth/login", response_model=SessionToken)
def login(payload: LoginRequest):
    user = db.users.find_one({"email": payload.email})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(payload.password, user["password_salt"], user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.get("verified"):
        raise HTTPException(status_code=403, detail="Email not verified")
    token = generate_token()
    session_doc = {"user_id": user["_id"], "token": token, "created_at": datetime.now(timezone.utc)}
    db.sessions.insert_one(session_doc)
    return SessionToken(token=token)


@app.get("/auth/me", response_model=UserPublic)
def me(user: AuthedUser = Depends(get_current_user)):
    return UserPublic(id=user.id, name=user.name, email=user.email, role=user.role, verified=True)


# Contractor Profiles
@app.get("/profile", response_model=ContractorProfileOut)
def get_profile(user: AuthedUser = Depends(get_current_user)):
    if user.role != "contractor":
        raise HTTPException(status_code=403, detail="Only contractors have profiles")
    prof = db.profiles.find_one({"user_id": ObjectId(user.id)})
    if not prof:
        # create empty profile
        prof_doc = {
            "user_id": ObjectId(user.id),
            "logo_url": None,
            "company_name": user.name,
            "categories": [],
            "experience": None,
            "past_projects": [],
            "contact_email": user.email,
            "contact_phone": None,
            "location": None,
            "rating": 0.0,
            "ratings_count": 0,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        }
        db.profiles.insert_one(prof_doc)
        prof = prof_doc
    return ContractorProfileOut(
        id=oid(prof.get("_id")),
        user_id=oid(prof["user_id"]),
        logo_url=prof.get("logo_url"),
        company_name=prof.get("company_name"),
        categories=prof.get("categories", []),
        experience=prof.get("experience"),
        past_projects=prof.get("past_projects", []),
        contact_email=prof.get("contact_email"),
        contact_phone=prof.get("contact_phone"),
        location=prof.get("location"),
        rating=prof.get("rating", 0.0),
        ratings_count=prof.get("ratings_count", 0),
    )


@app.put("/profile", response_model=ContractorProfileOut)
def update_profile(payload: ContractorProfileIn, user: AuthedUser = Depends(get_current_user)):
    if user.role != "contractor":
        raise HTTPException(status_code=403, detail="Only contractors have profiles")
    update = payload.model_dump()
    update["updated_at"] = datetime.now(timezone.utc)
    res = db.profiles.find_one_and_update(
        {"user_id": ObjectId(user.id)},
        {"$set": update},
        upsert=True,
        return_document=True,
    )
    # If find_one_and_update returns None with upsert, fetch it
    prof = res or db.profiles.find_one({"user_id": ObjectId(user.id)})
    return ContractorProfileOut(
        id=oid(prof.get("_id")),
        user_id=oid(prof["user_id"]),
        logo_url=prof.get("logo_url"),
        company_name=prof.get("company_name"),
        categories=prof.get("categories", []),
        experience=prof.get("experience"),
        past_projects=prof.get("past_projects", []),
        contact_email=prof.get("contact_email"),
        contact_phone=prof.get("contact_phone"),
        location=prof.get("location"),
        rating=prof.get("rating", 0.0),
        ratings_count=prof.get("ratings_count", 0),
    )


# File upload (store locally for MVP)
UPLOAD_DIR = os.path.join(os.getcwd(), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


@app.post("/upload")
def upload_file(file: UploadFile = File(...), user: AuthedUser = Depends(get_current_user)):
    filename = f"{datetime.utcnow().timestamp()}_{file.filename}"
    path = os.path.join(UPLOAD_DIR, filename)
    with open(path, "wb") as f:
        f.write(file.file.read())
    return {"url": f"/uploads/{filename}", "filename": filename}


@app.get("/uploads/{filename}")
def get_uploaded_file(filename: str):
    path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(path)


# Opportunities
@app.post("/opportunities", response_model=OpportunityOut)
def create_opportunity(payload: OpportunityCreate, user: AuthedUser = Depends(get_current_user)):
    if user.role != "developer":
        raise HTTPException(status_code=403, detail="Only developers can post opportunities")
    doc = payload.model_dump()
    doc.update({
        "developer_id": ObjectId(user.id),
        "created_at": datetime.now(timezone.utc),
    })
    res_id = db.opportunities.insert_one(doc).inserted_id
    out = db.opportunities.find_one({"_id": res_id})
    return OpportunityOut(
        id=oid(out["_id"]),
        developer_id=oid(out["developer_id"]),
        title=out["title"],
        category=out["category"],
        description=out["description"],
        files=out.get("files", []),
        deadline=out.get("deadline"),
        budget=out.get("budget"),
        location=out.get("location"),
        created_at=out["created_at"],
    )


@app.get("/opportunities", response_model=List[OpportunityOut])
def list_opportunities(category: Optional[str] = None, location: Optional[str] = None):
    filt: Dict[str, Any] = {}
    if category:
        filt["category"] = category
    if location:
        filt["location"] = location
    items = []
    for o in db.opportunities.find(filt).sort("created_at", -1):
        items.append(
            OpportunityOut(
                id=oid(o["_id"]),
                developer_id=oid(o["developer_id"]),
                title=o["title"],
                category=o["category"],
                description=o["description"],
                files=o.get("files", []),
                deadline=o.get("deadline"),
                budget=o.get("budget"),
                location=o.get("location"),
                created_at=o["created_at"],
            )
        )
    return items


@app.get("/opportunities/{op_id}", response_model=OpportunityOut)
def get_opportunity(op_id: str):
    o = db.opportunities.find_one({"_id": ObjectId(op_id)})
    if not o:
        raise HTTPException(status_code=404, detail="Not found")
    return OpportunityOut(
        id=oid(o["_id"]),
        developer_id=oid(o["developer_id"]),
        title=o["title"],
        category=o["category"],
        description=o["description"],
        files=o.get("files", []),
        deadline=o.get("deadline"),
        budget=o.get("budget"),
        location=o.get("location"),
        created_at=o["created_at"],
    )


# Proposals
@app.post("/opportunities/{op_id}/proposals", response_model=ProposalOut)
def submit_proposal(op_id: str, payload: ProposalCreate, user: AuthedUser = Depends(get_current_user)):
    if user.role != "contractor":
        raise HTTPException(status_code=403, detail="Only contractors can submit proposals")
    # Ensure opportunity exists
    o = db.opportunities.find_one({"_id": ObjectId(op_id)})
    if not o:
        raise HTTPException(status_code=404, detail="Opportunity not found")
    doc = payload.model_dump()
    doc.update({
        "opportunity_id": ObjectId(op_id),
        "contractor_id": ObjectId(user.id),
        "status": "submitted",
        "created_at": datetime.now(timezone.utc),
    })
    res_id = db.proposals.insert_one(doc).inserted_id
    p = db.proposals.find_one({"_id": res_id})
    return ProposalOut(
        id=oid(p["_id"]),
        opportunity_id=oid(p["opportunity_id"]),
        contractor_id=oid(p["contractor_id"]),
        amount=p.get("amount"),
        message=p.get("message"),
        attachments=p.get("attachments", []),
        timeline_weeks=p.get("timeline_weeks"),
        status=p.get("status", "submitted"),
        created_at=p["created_at"],
    )


@app.get("/proposals/mine", response_model=List[ProposalOut])
def my_proposals(user: AuthedUser = Depends(get_current_user)):
    if user.role != "contractor":
        raise HTTPException(status_code=403, detail="Only contractors can view their proposals")
    items: List[ProposalOut] = []
    for p in db.proposals.find({"contractor_id": ObjectId(user.id)}).sort("created_at", -1):
        items.append(
            ProposalOut(
                id=oid(p["_id"]),
                opportunity_id=oid(p["opportunity_id"]),
                contractor_id=oid(p["contractor_id"]),
                amount=p.get("amount"),
                message=p.get("message"),
                attachments=p.get("attachments", []),
                timeline_weeks=p.get("timeline_weeks"),
                status=p.get("status", "submitted"),
                created_at=p["created_at"],
            )
        )
    return items


@app.get("/proposals/for-me", response_model=List[ProposalOut])
def proposals_for_my_opportunities(user: AuthedUser = Depends(get_current_user)):
    if user.role != "developer":
        raise HTTPException(status_code=403, detail="Only developers can view proposals received")
    # Find opportunities owned by developer
    op_ids = [o["_id"] for o in db.opportunities.find({"developer_id": ObjectId(user.id)}, {"_id": 1})]
    items: List[ProposalOut] = []
    for p in db.proposals.find({"opportunity_id": {"$in": op_ids}}).sort("created_at", -1):
        items.append(
            ProposalOut(
                id=oid(p["_id"]),
                opportunity_id=oid(p["opportunity_id"]),
                contractor_id=oid(p["contractor_id"]),
                amount=p.get("amount"),
                message=p.get("message"),
                attachments=p.get("attachments", []),
                timeline_weeks=p.get("timeline_weeks"),
                status=p.get("status", "submitted"),
                created_at=p["created_at"],
            )
        )
    return items


class ProposalStatusUpdate(BaseModel):
    status: str  # submitted / viewed / selected


@app.patch("/proposals/{proposal_id}/status")
def update_proposal_status(proposal_id: str, payload: ProposalStatusUpdate, user: AuthedUser = Depends(get_current_user)):
    if user.role != "developer":
        raise HTTPException(status_code=403, detail="Only developers can update proposal status")
    p = db.proposals.find_one({"_id": ObjectId(proposal_id)})
    if not p:
        raise HTTPException(status_code=404, detail="Proposal not found")
    # Ensure the proposal belongs to one of user's opportunities
    o = db.opportunities.find_one({"_id": p["opportunity_id"]})
    if oid(o["developer_id"]) != user.id:
        raise HTTPException(status_code=403, detail="Not allowed")
    if payload.status not in ["submitted", "viewed", "selected"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    db.proposals.update_one({"_id": p["_id"]}, {"$set": {"status": payload.status, "updated_at": datetime.now(timezone.utc)}})
    return {"message": "Status updated"}


# Developer dashboard data
class DeveloperDashboard(BaseModel):
    my_opportunities: List[OpportunityOut]
    proposals_received: List[ProposalOut]


@app.get("/dashboard/developer", response_model=DeveloperDashboard)
def developer_dashboard(user: AuthedUser = Depends(get_current_user)):
    if user.role != "developer":
        raise HTTPException(status_code=403, detail="Only developers")
    ops = list_opportunities()  # all
    my_ops = [o for o in ops if o.developer_id == user.id]
    props = proposals_for_my_opportunities(user)
    return DeveloperDashboard(my_opportunities=my_ops, proposals_received=props)


class ContractorDashboard(BaseModel):
    opportunities: List[OpportunityOut]
    my_proposals: List[ProposalOut]


@app.get("/dashboard/contractor", response_model=ContractorDashboard)
def contractor_dashboard(user: AuthedUser = Depends(get_current_user)):
    if user.role != "contractor":
        raise HTTPException(status_code=403, detail="Only contractors")
    ops = list_opportunities()
    props = my_proposals(user)
    return ContractorDashboard(opportunities=ops, my_proposals=props)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
