"""Fixture data for SEC-INSECURE-CORS tests. Never executed."""

from fastapi.middleware.cors import CORSMiddleware


def configure(app):
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    return app
