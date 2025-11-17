"""
Database Schemas for FoodRankr

Each Pydantic model below represents a MongoDB collection. The collection
name is the lowercase of the class name (e.g., User -> "user").
"""

from typing import Optional, List
from pydantic import BaseModel, Field, EmailStr
from datetime import date, datetime

# Auth & org models
class User(BaseModel):
    email: EmailStr = Field(..., description="Work email")
    hashed_password: str = Field(..., description="BCrypt hashed password")
    full_name: str = Field(..., description="Employee full name")
    country: str = Field(..., description="Country selected at onboarding")
    company_id: Optional[str] = Field(None, description="Reference to company _id")
    cafe_name: Optional[str] = Field(None, description="Cafe name at office")
    is_admin: bool = Field(False, description="Admin privileges")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class Company(BaseModel):
    name: str = Field(..., description="Company name")
    country: str = Field(..., description="Country")
    approved: bool = Field(False, description="Whether admin approved company")
    created_by: Optional[str] = Field(None, description="User id who requested creation")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class Dish(BaseModel):
    name: str = Field(..., description="Main dish name")
    description: Optional[str] = Field(None, description="Short description")

class FoodRank(BaseModel):
    user_id: str = Field(..., description="User who posted")
    company_id: str = Field(..., description="Company context")
    cafe_name: str = Field(..., description="Cafe name")
    country: str = Field(..., description="Country")
    date: date = Field(..., description="Ranking date (daily)")
    dish: str = Field(..., description="Main dish user took")
    rating: int = Field(..., ge=1, le=5, description="1-5 rating")
    image_url: Optional[str] = Field(None, description="Stored image URL or data URI")
    comment: Optional[str] = Field(None, description="Optional note")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class PendingCompanyRequest(BaseModel):
    name: str
    country: str
    requested_by: str
    approved: bool = False
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
