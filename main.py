import os
from datetime import datetime, timedelta, date
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from pydantic import BaseModel, EmailStr

from database import db
from bson import ObjectId

# Environment and security settings
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

app = FastAPI(title="FoodRankr API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Utilities
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    user_id: Optional[str] = None

# Data models (thin versions for I/O)
class RegisterModel(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    country: str
    company: Optional[str] = None  # company id or name for request
    cafe_name: Optional[str] = None

class LoginModel(BaseModel):
    email: EmailStr
    password: str

class ApproveCompanyModel(BaseModel):
    company_id: str
    approved: bool

class CompanyCreateModel(BaseModel):
    name: str
    country: str

class RankCreateModel(BaseModel):
    date: date
    dish: str
    rating: int
    comment: Optional[str] = None
    image_url: Optional[str] = None

class ProfileUpdateModel(BaseModel):
    country: Optional[str] = None
    company_id: Optional[str] = None
    cafe_name: Optional[str] = None
    full_name: Optional[str] = None

# Auth helpers

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_user_by_email(email: str):
    return db["user"].find_one({"email": email})


def serialize_user(user: dict):
    if not user:
        return None
    return {
        "_id": str(user["_id"]),
        "email": user.get("email"),
        "full_name": user.get("full_name"),
        "country": user.get("country"),
        "company_id": user.get("company_id"),
        "cafe_name": user.get("cafe_name"),
        "is_admin": user.get("is_admin", False),
        "created_at": user.get("created_at"),
        "updated_at": user.get("updated_at"),
    }


def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db["user"].find_one({"_id": ObjectId(user_id)})
    if not user:
        raise credentials_exception
    return user


def require_admin(user = Depends(get_current_user)):
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user


@app.get("/")
def root():
    return {"message": "FoodRankr backend running"}


# Auth routes
@app.post("/auth/register", response_model=Token)
def register(payload: RegisterModel):
    existing = get_user_by_email(payload.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Determine company id or create pending request
    company_id = None
    if payload.company:
        # Try as ObjectId
        comp = None
        if ObjectId.is_valid(str(payload.company)):
            comp = db["company"].find_one({"_id": ObjectId(str(payload.company))})
        if not comp:
            comp = db["company"].find_one({"name": payload.company})
        if comp:
            company_id = str(comp["_id"]) if isinstance(comp["_id"], ObjectId) else comp["_id"]
        else:
            db["pendingcompanyrequest"].insert_one({
                "name": payload.company,
                "country": payload.country,
                "requested_by": None,
                "approved": False,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
            })
    hashed = get_password_hash(payload.password)
    user_doc = {
        "email": payload.email,
        "hashed_password": hashed,
        "full_name": payload.full_name,
        "country": payload.country,
        "company_id": company_id,
        "cafe_name": payload.cafe_name,
        "is_admin": False,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    result = db["user"].insert_one(user_doc)

    access_token = create_access_token({"sub": str(result.inserted_id)})
    return Token(access_token=access_token)


@app.post("/auth/login", response_model=Token)
def login(payload: LoginModel):
    user = get_user_by_email(payload.email)
    if not user or not verify_password(payload.password, user.get("hashed_password", "")):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token = create_access_token({"sub": str(user["_id"])})
    return Token(access_token=access_token)


@app.get("/auth/me")
def me(user=Depends(get_current_user)):
    return serialize_user(user)


# Company endpoints
@app.get("/companies")
def list_companies(country: Optional[str] = None, approved: Optional[bool] = None):
    query = {}
    # default: only approved
    if approved is None:
        query["approved"] = True
    else:
        query["approved"] = approved
    if country:
        query["country"] = country
    comps = list(db["company"].find(query).sort("name", 1))
    for c in comps:
        c["_id"] = str(c["_id"]) 
    return comps

@app.post("/companies")
def create_company(data: CompanyCreateModel, user=Depends(get_current_user)):
    # normal users can request new company (unapproved), admins can auto approve
    approved_flag = bool(user.get("is_admin"))
    existing = db["company"].find_one({"name": data.name, "country": data.country})
    if existing:
        raise HTTPException(status_code=400, detail="Company already exists")
    doc = {
        "name": data.name,
        "country": data.country,
        "approved": approved_flag,
        "created_by": str(user["_id"]),
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    result = db["company"].insert_one(doc)
    return {"_id": str(result.inserted_id), **doc}

@app.post("/admin/companies/approve")
def approve_company(payload: ApproveCompanyModel, admin=Depends(require_admin)):
    cid = payload.company_id
    if not ObjectId.is_valid(cid):
        raise HTTPException(status_code=400, detail="Invalid company id")
    res = db["company"].update_one({"_id": ObjectId(cid)}, {"$set": {"approved": payload.approved, "updated_at": datetime.utcnow()}})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Company not found")
    return {"status": "ok"}


# User profile endpoints
@app.get("/user/profile")
def get_profile(user=Depends(get_current_user)):
    return serialize_user(user)

@app.put("/user/profile")
def update_profile(data: ProfileUpdateModel, user=Depends(get_current_user)):
    updates = {}
    if data.country is not None:
        updates["country"] = data.country
    if data.cafe_name is not None:
        updates["cafe_name"] = data.cafe_name
    if data.full_name is not None:
        updates["full_name"] = data.full_name
    if data.company_id is not None:
        if data.company_id and not ObjectId.is_valid(data.company_id):
            raise HTTPException(status_code=400, detail="Invalid company id")
        # ensure company approved before setting
        comp = db["company"].find_one({"_id": ObjectId(data.company_id)})
        if not comp or not comp.get("approved"):
            raise HTTPException(status_code=400, detail="Company not approved")
        updates["company_id"] = data.company_id
    if not updates:
        return serialize_user(user)
    updates["updated_at"] = datetime.utcnow()
    db["user"].update_one({"_id": user["_id"]}, {"$set": updates})
    user.update(updates)
    return serialize_user(user)


# Ranking endpoints
@app.get("/ranks")
def list_ranks(company_id: Optional[str] = None, date_str: Optional[str] = None):
    query = {}
    if company_id and ObjectId.is_valid(company_id):
        query["company_id"] = company_id
    if date_str:
        try:
            d = date.fromisoformat(date_str)
            query["date"] = d.isoformat()
        except Exception:
            pass
    ranks = list(db["foodrank"].find(query).sort("created_at", -1).limit(50))
    for r in ranks:
        r["_id"] = str(r["_id"]) 
    return ranks

@app.post("/ranks")
def create_rank(data: RankCreateModel, user=Depends(get_current_user)):
    # require company selected or user's company
    company_id = user.get("company_id")
    if not company_id:
        raise HTTPException(status_code=400, detail="User has no company assigned")
    if data.rating < 1 or data.rating > 5:
        raise HTTPException(status_code=400, detail="Rating must be 1-5")
    doc = {
        "user_id": str(user["_id"]) if isinstance(user["_id"], ObjectId) else user["_id"],
        "company_id": company_id,
        "cafe_name": user.get("cafe_name") or "",
        "country": user.get("country"),
        "date": data.date.isoformat(),
        "dish": data.dish,
        "rating": data.rating,
        "image_url": data.image_url,
        "comment": data.comment,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    result = db["foodrank"].insert_one(doc)
    return {"_id": str(result.inserted_id), **doc}


# Simple admin stats
@app.get("/admin/stats")
def admin_stats(admin=Depends(require_admin)):
    users = db["user"].count_documents({})
    companies = db["company"].count_documents({})
    ranks = db["foodrank"].count_documents({})
    pending = db["company"].count_documents({"approved": False})
    return {"users": users, "companies": companies, "ranks": ranks, "pending_companies": pending}


# Health
@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
