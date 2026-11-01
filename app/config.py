import os
from pathlib import Path


def _load_secret(name: str, default: str | None = None) -> str:
    """Load a secret from a mounted file (Kubernetes) or an environment variable.

    File path can be overridden with <NAME>_FILE; defaults to /run/secrets/<name.lower()>.
    Falls back to the plain environment variable for local development / docker run.
    """
    path = Path(os.environ.get(f"{name}_FILE", f"/run/secrets/{name.lower()}"))
    if path.is_file():
        value = path.read_text(encoding="utf-8").strip()
        if value:
            return value

    value = os.environ.get(name)
    if value:
        return value

    if default is not None:
        return default
    raise RuntimeError(f"Required secret {name} not configured")


# --- JWT configuration ---
SECRET_KEY = _load_secret("SECRET_KEY")
ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# --- Database configuration ---
# SQLite default preserved for local dev and tests. Production overrides via DATABASE_URL.
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./vulntracker.db")

# --- Secrets previously hardcoded in source (now loaded from file or env) ---
DB_USER = _load_secret("DB_USER", default="vulntracker_app")
DB_PASSWORD = _load_secret("DB_PASSWORD")
ADMIN_API_KEY = _load_secret("ADMIN_API_KEY")

# --- Internal service configuration ---
NOTIFY_SERVICE_URL = os.environ.get("NOTIFY_SERVICE_URL", "http://localhost:3001")