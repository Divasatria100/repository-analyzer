"""Application settings (foundation skeleton, no business logic)."""

from pydantic import BaseModel


class Settings(BaseModel):
    app_name: str = "RepoLens API"


settings = Settings()
