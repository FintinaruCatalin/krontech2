from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.phishing import router as phishing_router
from app.api.url import router as url_router
from app.core.config import settings


# This creates the FastAPI application object.
# Uvicorn will import this variable when we run: uvicorn app.main:app --reload
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.PROJECT_VERSION,
)


# CORS allows the frontend app to call this backend from the browser.
# For this MVP we only allow the local Angular development URLs.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Routers keep endpoints organized in separate files.
# This adds the phishing endpoints under the /analyze path.
app.include_router(phishing_router, prefix="/analyze")
app.include_router(url_router, prefix="/analyze")


# This health check is useful for quickly testing that the server is running.
@app.get("/")
def health_check():
    return {
        "status": "ok",
        "service": "anti-scam-backend",
    }
