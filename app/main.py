from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import SQLAlchemyError

from app.api.auth import router as auth_router
from app.api.history import router as history_router
from app.api.phishing import router as phishing_router
from app.api.stats import router as stats_router
from app.api.url import router as url_router
from app.core.config import settings
from app.db import models
from app.db.database import Base, engine
from app.services.ml.predictor import log_local_model_status


# This creates the FastAPI application object.
# Uvicorn will import this variable when we run: uvicorn app.main:app --reload
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.PROJECT_VERSION,
)


# CORS allows the frontend app to call this backend from the browser.
# For this MVP we allow local Angular development URLs on any localhost port.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_origin_regex=r"http://localhost:\d+|http://127\.0\.0\.1:\d+",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Routers keep endpoints organized in separate files.
# This adds the phishing endpoints under the /analyze path.
app.include_router(phishing_router, prefix="/analyze")
app.include_router(url_router, prefix="/analyze")
app.include_router(auth_router)
app.include_router(history_router)
app.include_router(stats_router)


@app.on_event("startup")
def create_database_tables():
    # Importing models above registers tables before SQLAlchemy creates them.
    try:
        Base.metadata.create_all(bind=engine)
    except SQLAlchemyError:
        pass

    log_local_model_status()


# This health check is useful for quickly testing that the server is running.
@app.get("/")
def health_check():
    return {
        "status": "ok",
        "service": "anti-scam-backend",
    }
