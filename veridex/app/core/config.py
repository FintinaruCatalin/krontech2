from pydantic import BaseModel


# Settings keeps project-level configuration in one place.
# For this beginner MVP we use fixed values instead of environment variables.
class Settings(BaseModel):
    PROJECT_NAME: str = "Anti Scam Backend"
    PROJECT_VERSION: str = "0.1.0"
    ALLOWED_ORIGINS: list[str] = [
        "http://localhost:4200",
        "http://127.0.0.1:4200",
    ]


# Other files import this single settings object instead of repeating values.
settings = Settings()
