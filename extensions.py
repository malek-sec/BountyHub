from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

db            = SQLAlchemy()
login_manager = LoginManager()
limiter       = Limiter(key_func=get_remote_address,
                        default_limits=["200 per day", "50 per hour"],
                        storage_uri="memory://")
csrf          = CSRFProtect()

login_manager.login_view = 'auth.login'  # used by page routes; /api/* routes return 401 JSON via unauthorized_handler in app.py
