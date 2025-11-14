
# import os
# from flask import Flask, jsonify, session
# from urllib.parse import quote_plus
# from werkzeug.middleware.proxy_fix import ProxyFix

# from db_config import db
# from flask_cors import CORS

# # Blueprints
# from auth.routes import auth_bp
# from columns import columns_bp
# from ipc import ipc_bp
# from reference import reference_bp
# from strings import strings_bp
# from report import report_bp
# from log import log_bp

# def create_app():
#     app = Flask(__name__)

#     # ---------- Session / Cookie ----------
#     app.config["SESSION_COOKIE_NAME"] = "elicita_session"
#     app.config["SESSION_COOKIE_SAMESITE"] = "None"   # cross-site
#     app.config["SESSION_COOKIE_SECURE"] = False      # True in HTTPS prod
#     app.config["SESSION_COOKIE_HTTPONLY"] = True
#     app.config["SESSION_COOKIE_PATH"] = "/"
#     # app.config["SESSION_COOKIE_DOMAIN"] = ".datasolve-analytics.net"  # when on domain

#     app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
#     app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "vasanthkv47")

#     # ---------- Database ----------
#     user = os.getenv("DB_USER", "appsadmin")
#     pwd = os.getenv("DB_PWD", "appsadmin2025")
#     host = os.getenv("DB_HOST", "34.93.75.171")
#     dbname = os.getenv("DB_NAME", "Elicita_V2")

#     app.config["SQLALCHEMY_DATABASE_URI"] = (
#         f"mysql+pymysql://{user}:{quote_plus(pwd)}@{host}:3306/{dbname}?charset=utf8mb4"
#     )
#     app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

#     # ---------- CORS ----------
#     CORS(
#         app,
#         origins=[
#             "http://localhost:5173",
#             "http://34.180.7.64:9000",
#             "http://34.63.142.140:3090",
#             "http://localhost:5174",
#             "http://localhost:5175",
#             "http://23.251.147.229:9000",
#             # add production origins here
#         ],
#         supports_credentials=True,
#     )

#     # ---------- Init & Routes ----------
#     db.init_app(app)
#     app.register_blueprint(auth_bp, url_prefix="/api/auth")

#     from assignee import api_bp as assignee_bp
#     app.register_blueprint(assignee_bp)

#     app.register_blueprint(columns_bp)
#     app.register_blueprint(ipc_bp)
#     app.register_blueprint(reference_bp)
#     app.register_blueprint(strings_bp)
#     app.register_blueprint(report_bp)
#     app.register_blueprint(log_bp)

#     # ---------- Health & Debug ----------
#     @app.get("/health")
#     def health():
#         return {"ok": True}, 200

#     @app.get("/api/debug/session")
#     def whoami():
#         return {
#             "user_name": session.get("user_name"),
#             "user_email": session.get("user_email"),
#             "login_time": session.get("login_time"),
#         }, 200

#     @app.errorhandler(404)
#     def not_found_error(error):
#         return jsonify({"success": False, "message": "The requested resource was not found."}), 404

#     @app.errorhandler(500)
#     def internal_error(error):
#         db.session.rollback()
#         return jsonify({"success": False, "message": "An internal server error occurred."}), 500

#     return app

# if __name__ == "__main__":
#     app = create_app()
#     app.run(host="0.0.0.0", port=3070, debug=True)
import os
from flask import Flask, jsonify, session
from urllib.parse import quote_plus
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_cors import CORS
from db_config import db

# --- Blueprints ---
from auth.routes import auth_bp
from columns import columns_bp
from ipc import ipc_bp
from reference import reference_bp
from strings import strings_bp
from report import report_bp
from log import log_bp


def create_app():
    app = Flask(__name__)

    # ---------------- Env & Frontend origins ----------------
    # APP_ENV: "dev" (HTTP) or "prod" (HTTPS). Default prod.
    APP_ENV = os.getenv("APP_ENV", "prod").lower()

    # Comma-separated list of allowed frontends (scheme+host+port)
    FRONTEND_ORIGINS = (os.getenv("FRONTEND_ORIGINS", "")
                        or "http://localhost:5173,http://127.0.0.1:5173").split(",")

    # ---------------- Session / Cookie ----------------
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "vasanthkv47")
    app.config["SESSION_COOKIE_NAME"] = "elicita_session"
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_PATH"] = "/"

    COOKIE_DOMAIN = os.getenv("SESSION_COOKIE_DOMAIN", "").strip()
    if COOKIE_DOMAIN:
        app.config["SESSION_COOKIE_DOMAIN"] = COOKIE_DOMAIN

    if APP_ENV == "dev":
        # Works over HTTP for local/dev testing
        app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
        app.config["SESSION_COOKIE_SECURE"] = False
        print("✅ DEV MODE: SameSite=Lax, Secure=False (HTTP OK)")
    else:
        # Requires HTTPS on the frontend origin
        app.config["SESSION_COOKIE_SAMESITE"] = "None"
        app.config["SESSION_COOKIE_SECURE"] = True
        print("🔐 PROD MODE: SameSite=None, Secure=True (HTTPS required)")

    # Respect X-Forwarded-* when behind a proxy/ingress
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

    # ---------------- Database ----------------
    user = os.getenv("DB_USER", "appsadmin")
    pwd = os.getenv("DB_PWD", "appsadmin2025")
    dbname = os.getenv("DB_NAME", "Elicita_V2")

    # For App Engine (prod) we use Unix socket: /cloudsql/PROJECT:REGION:INSTANCE
    instance_conn_name = os.getenv(
        "INSTANCE_CONNECTION_NAME",
        "theta-messenger-459613-p7:asia-south1:appsadmin"
    )

    if APP_ENV == "dev":
        # Local / VM / Cloud Shell – connect by IP
        host = os.getenv("DB_HOST", "34.93.75.171")
        app.config["SQLALCHEMY_DATABASE_URI"] = (
            f"mysql+pymysql://{user}:{quote_plus(pwd)}@{host}:3306/{dbname}?charset=utf8mb4"
        )
        print(f"💻 DEV DB via TCP → {host}")
    else:
        # App Engine standard – connect via Cloud SQL Unix socket
        unix_socket_path = f"/cloudsql/{instance_conn_name}"

        app.config["SQLALCHEMY_DATABASE_URI"] = (
            f"mysql+pymysql://{user}:{quote_plus(pwd)}@/{dbname}"
            f"?unix_socket={quote_plus(unix_socket_path)}&charset=utf8mb4"
        )
        print(f"☁️ PROD DB via Unix socket → {unix_socket_path}")

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # ---------------- CORS ----------------
    cors_origins = [o.strip() for o in FRONTEND_ORIGINS if o.strip()]
    CORS(app, origins=cors_origins, supports_credentials=True)

    # ---------------- Init DB & Blueprints ----------------
    db.init_app(app)
    app.register_blueprint(auth_bp, url_prefix="/api/auth")

    from assignee import api_bp as assignee_bp
    app.register_blueprint(assignee_bp)

    app.register_blueprint(columns_bp)
    app.register_blueprint(ipc_bp)
    app.register_blueprint(reference_bp)
    app.register_blueprint(strings_bp)
    app.register_blueprint(report_bp)
    app.register_blueprint(log_bp)

    # ---------------- Health & Debug ----------------
    @app.get("/health")
    def health():
        return {"ok": True}, 200

    @app.get("/api/debug/session")
    def whoami():
        return {
            "user_name": session.get("user_name"),
            "user_email": session.get("user_email"),
            "login_time": session.get("login_time"),
        }, 200

    # ---------------- Error Handlers ----------------
    @app.errorhandler(404)
    def not_found_error(error):
        return jsonify({"success": False, "message": "The requested resource was not found."}), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return jsonify({"success": False, "message": "An internal server error occurred."}), 500

    return app


# 🔴 IMPORTANT: global app for gunicorn (app:app)
app = create_app()

if __name__ == "__main__":
    # Local run
    app.run(host="0.0.0.0", port=3070, debug=True)
