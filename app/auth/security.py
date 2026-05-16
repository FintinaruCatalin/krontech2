import os
from datetime import datetime, timedelta, timezone

from jose import jwt
from passlib.context import CryptContext


# Development fallback only. Set SECRET_KEY in the environment before production use.
SECRET_KEY = os.getenv("SECRET_KEY", "temporary-dev-secret-key-change-me")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return password_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_context.verify(plain_password, hashed_password)


def create_access_token(data: dict) -> str:
    token_data = data.copy()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token_data.update({"exp": expires_at})

    return jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)
