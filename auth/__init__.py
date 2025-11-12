# auth/__init__.py
from .routes import auth_bp  # relative import avoids grabbing top-level routes.py
__all__ = ["auth_bp"]
