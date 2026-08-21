import json
import os
import secrets as _secrets

from flask import Flask, jsonify, redirect, request, url_for
from werkzeug.security import generate_password_hash

from flask_migrate import Migrate

from config import Config
from extensions import csrf, db, limiter, login_manager
from models import FeatureFlag, User
from routes import admin_bp, auth_bp, payouts_bp, programs_bp, scans_bp, vuln_bp
from services.scan_service import ScanService


def create_app(config_class=Config) -> Flask:
    Config.validate()

    app = Flask(__name__)
    app.config.from_object(config_class)

    # Ensure required directories exist
    os.makedirs(app.config['UPLOAD_FOLDER'],      exist_ok=True)
    os.makedirs(app.config['SCREENSHOTS_FOLDER'], exist_ok=True)

    # ── Init extensions ───────────────────────────────────────────────────────
    db.init_app(app)
    Migrate(app, db)
    login_manager.init_app(app)
    limiter.init_app(app)
    csrf.init_app(app)

    # ── User loader ───────────────────────────────────────────────────────────
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # ── Unauthorized handler ──────────────────────────────────────────────────
    # API routes must return 401 JSON (not an HTML login-page redirect) so that
    # the JS polling loop can detect session expiry cleanly instead of crashing
    # with "Unexpected token '<'" when it tries to parse the HTML as JSON.
    @login_manager.unauthorized_handler
    def handle_unauthorized():
        if request.path.startswith('/api/'):
            return jsonify({"error": "Authentication required", "redirect": "/login"}), 401
        return redirect(url_for('auth.login', next=request.url))

    # ── Register blueprints ───────────────────────────────────────────────────
    app.register_blueprint(auth_bp)
    app.register_blueprint(vuln_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(programs_bp)
    app.register_blueprint(payouts_bp)

    # ── Jinja2 filters ────────────────────────────────────────────────────────
    app.jinja_env.filters['from_json'] = json.loads

    # ── Context processor ─────────────────────────────────────────────────────
    from models.feature_flag import FeatureFlagService

    @app.context_processor
    def inject_globals():
        from flask_login import current_user

        def feature_enabled(flag_name):
            user_id = current_user.id if current_user.is_authenticated else None
            return FeatureFlagService.is_enabled(flag_name, user_id)

        return dict(
            feature_enabled=feature_enabled,
            scan_engine_available=ScanService._engine_available,
        )

    # ── Scan engine ───────────────────────────────────────────────────────────
    ScanService.init_engine(app.config['V2_ROOT'])

    # ── DB bootstrap ─────────────────────────────────────────────────────────
    with app.app_context():
        db.create_all()
        _seed_defaults(app)

    return app


def _seed_defaults(app: Flask) -> None:
    """Create admin user and default feature flags on first boot."""
    if not User.query.filter_by(username='admin').first():
        _init_pw = os.environ.get("ADMIN_INIT_PASSWORD", "").strip()
        if not _init_pw:
            _init_pw = _secrets.token_urlsafe(20)
            print(
                f"\n{'='*60}\n"
                f"  [!] ADMIN INITIAL PASSWORD (printed once — save it now):\n"
                f"      {_init_pw}\n"
                f"{'='*60}\n",
                flush=True,
            )
        admin = User(
            username='admin',
            password=generate_password_hash(_init_pw, method='pbkdf2:sha256'),
            email='admin@bountyhub.local',
            role='admin',
        )
        db.session.add(admin)

    default_flags = [
        ('pdf_export',      'تصدير التقارير كملفات PDF', True,  100),
        ('bulk_operations', 'العمليات الجماعية',          False,   0),
        ('advanced_search', 'البحث المتقدم',              True,  100),
        ('dark_mode',       'الوضع الداكن',               True,  100),
    ]
    for name, desc, enabled, rollout in default_flags:
        if not FeatureFlag.query.filter_by(name=name).first():
            db.session.add(FeatureFlag(
                name=name, description=desc,
                enabled=enabled, rollout_percentage=rollout,
            ))

    db.session.commit()


if __name__ == '__main__':
    _debug = os.environ.get("FLASK_DEBUG", "0").strip() == "1"
    create_app().run(debug=_debug, host="127.0.0.1", port=5000,
                     use_reloader=False)
