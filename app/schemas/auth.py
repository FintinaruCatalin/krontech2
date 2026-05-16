from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class UserCreate(BaseModel):
    email: str
    username: str | None = None
    full_name: str | None = None
    password: str


class UserLogin(BaseModel):
    email: str
    password: str


class UserResponse(BaseModel):
    id: int
    email: str
    username: str | None = None
    full_name: str | None = None
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
