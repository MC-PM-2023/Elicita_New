# import os
# from flask import Flask, jsonify
# from urllib.parse import quote_plus
# from auth.routes import auth_bp
# from db_config import db 
# from columns import columns_bp 
# from ipc import ipc_bp
# from reference import reference_bp
# from strings import strings_bp
# from report import report_bp
# from log import log_bp


# def create_app():
#     app = Flask(__name__)
#     app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "vasanthkv47")

#     user = os.getenv("DB_USER", "appsadmin")
#     pwd = os.getenv("DB_PWD", "appsadmin2025")
#     host = os.getenv("DB_HOST", "34.93.75.171")
#     dbname = os.getenv("DB_NAME", "Elicita_V2")

#     app.config["SQLALCHEMY_DATABASE_URI"] = (
#         f"mysql+pymysql://{user}:{quote_plus(pwd)}@{host}:3306/{dbname}?charset=utf8mb4"
#     )
#     app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

#     db.init_app(app)
#     app.register_blueprint(auth_bp, url_prefix="/api/auth")


#     #from auth import auth_bp
#     from assignee import api_bp as assignee_bp
#     #app.register_blueprint(auth_bp)
#     app.register_blueprint(assignee_bp)
#     app.register_blueprint(columns_bp)
#     app.register_blueprint(ipc_bp)
#     app.register_blueprint(reference_bp)
#     app.register_blueprint(strings_bp)
#     app.register_blueprint(report_bp)
#     app.register_blueprint(log_bp)

#     @app.get("/health")
#     def health():
#         return {"ok": True}, 200

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






#cors
# import os
# from flask import Flask, jsonify
# from urllib.parse import quote_plus
# from auth.routes import auth_bp
# from db_config import db 
# from columns import columns_bp 
# from ipc import ipc_bp
# from reference import reference_bp
# from strings import strings_bp
# from report import report_bp
# from flask_cors import CORS
# from log import log_bp

# def create_app():
#     app = Flask(__name__)
#     app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "vasanthkv47")

#     user = os.getenv("DB_USER", "appsadmin")
#     pwd = os.getenv("DB_PWD", "appsadmin2025")
#     host = os.getenv("DB_HOST", "34.93.75.171")
#     dbname = os.getenv("DB_NAME", "Elicita_V2")

#     app.config["SQLALCHEMY_DATABASE_URI"] = (
#         f"mysql+pymysql://{user}:{quote_plus(pwd)}@{host}:3306/{dbname}?charset=utf8mb4"
#     )
#     app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

#     # <--- FIX 1: Added 'supports_credentials=True' and fixed syntax error in list
#     CORS(app, 
#          origins=[
#              "http://localhost:5173", 
#              "http://34.180.7.64:9000",
#              "http://34.63.142.140:3090",
#              "http://localhost:5174",  
#              "http://localhost:5175"
#          ],
#          supports_credentials=True  # <--- THIS IS ESSENTIAL FOR COOKIES
#     )

#     # <--- FIX 2: ADDED SESSION COOKIE CONFIG ---
#     # This tells browsers it's okay to send this cookie cross-origin
#     app.config["SESSION_COOKIE_SAMESITE"] = "None"
#     app.config["SESSION_COOKIE_SECURE"] = False  # Set to True only if your frontend is HTTPS
#     # ------------------------------------------

#     db.init_app(app)
#     app.register_blueprint(auth_bp, url_prefix="/api/auth")


#     #from auth import auth_bp
#     from assignee import api_bp as assignee_bp
    
#     # <--- FIX 3: Fixed indentation for this line
#     app.register_blueprint(assignee_bp) 
#     app.register_blueprint(columns_bp)
#     app.register_blueprint(ipc_bp)
#     app.register_blueprint(reference_bp)
#     app.register_blueprint(strings_bp)
#     app.register_blueprint(report_bp)
#     app.register_blueprint(log_bp)

#     @app.get("/health")
#     def health():
#         return {"ok": True}, 200

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





# import os
# from flask import Flask, jsonify
# from urllib.parse import quote_plus
# from werkzeug.middleware.proxy_fix import ProxyFix 
# from auth.routes import auth_bp
# from db_config import db 
# from columns import columns_bp 
# from ipc import ipc_bp
# from reference import reference_bp
# from strings import strings_bp
# from report import report_bp
# from flask_cors import CORS
# from log import log_bp

# def create_app():
#     app = Flask(__name__)
    
    
#     app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

#     app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "vasanthkv47")

#     user = os.getenv("DB_USER", "appsadmin")
#     pwd = os.getenv("DB_PWD", "appsadmin2025")
#     host = os.getenv("DB_HOST", "34.93.75.171")
#     dbname = os.getenv("DB_NAME", "Elicita_V2")

#     app.config["SQLALCHEMY_DATABASE_URI"] = (
#         f"mysql+pymysql://{user}:{quote_plus(pwd)}@{host}:3306/{dbname}?charset=utf8mb4"
#     )
#     app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

#     CORS(app, 
#          origins=[
#              "http://localhost:5173", 
#              "http://34.180.7.64:9000",
#              "http://34.63.142.140:3090",
#              "http://localhost:5174",  
#              "http://localhost:5175",
#              "http://23.251.147.229:9000"
#          ],
#          supports_credentials=True 
#     )

    
#     app.config["SESSION_COOKIE_SAMESITE"] = "None"
   
#     app.config["SESSION_COOKIE_SECURE"] = True  
 

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

#     @app.get("/health")
#     def health():
#         return {"ok": True}, 200

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





#final 
# import os
# from flask import Flask, jsonify, session
# from urllib.parse import quote_plus
# from werkzeug.middleware.proxy_fix import ProxyFix

# from auth.routes import auth_bp
# from db_config import db
# from columns import columns_bp
# from ipc import ipc_bp
# from reference import reference_bp
# from strings import strings_bp
# from report import report_bp
# from flask_cors import CORS
# from log import log_bp


# def create_app():
#     app = Flask(__name__)

#     # ---------- Session / Cookie configuration (ADD/KEEP THIS) ----------
#     # Cross-site cookies require SameSite=None and Secure=True (must be HTTPS in prod)
#     app.config["SESSION_COOKIE_NAME"] = "elicita_session"
#     app.config["SESSION_COOKIE_SAMESITE"] = "None"   # allow cross-site requests
#     app.config["SESSION_COOKIE_SECURE"] = True       # must be HTTPS in prod
#     app.config["SESSION_COOKIE_HTTPONLY"] = True     # protect from JS access
#     app.config["SESSION_COOKIE_PATH"] = "/"
#     # If you serve on a domain (recommended), uncomment and set your parent domain:
#     # app.config["SESSION_COOKIE_DOMAIN"] = ".datasolve-analytics.net"
#     # -------------------------------------------------------------------

#     # Respect X-Forwarded-* headers when behind a proxy / load balancer
#     app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

#     # Secret key for session signing
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
#     # Must allow credentials and list exact origins (no '*') for cookies to flow.
#     CORS(
#         app,
#         origins=[
#             "http://localhost:5173",
#             "http://34.180.7.64:9000",
#             "http://34.63.142.140:3090",
#             "http://localhost:5174",
#             "http://localhost:5175",
#             "http://23.251.147.229:9000",
#             # Add your production frontend(s) here, e.g.:
#             # "https://your-frontend.datasolve-analytics.net",
#         ],
#         supports_credentials=True,
#     )

#     # ---------- Initialize DB and register blueprints ----------
#     db.init_app(app)
#     app.register_blueprint(auth_bp, url_prefix="/api/auth")

#     # If you have an assignee blueprint in assignee.py:
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
#         """Quick check to verify session cookie is received by the server."""
#         return {
#             "user_name": session.get("user_name"),
#             "user_email": session.get("user_email"),
#             "login_time": session.get("login_time"),
#         }, 200

#     # ---------- Error handlers ----------
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





#new
# import os
# from flask import Flask, jsonify, session
# from urllib.parse import quote_plus
# from werkzeug.middleware.proxy_fix import ProxyFix

# from auth.routes import auth_bp
# from db_config import db
# from columns import columns_bp
# from ipc import ipc_bp
# from reference import reference_bp
# from strings import strings_bp
# from report import report_bp
# from flask_cors import CORS
# from log import log_bp


# def create_app():
#     app = Flask(__name__)

#     # Detect environment: "dev" or "prod"
#     APP_ENV = os.getenv("APP_ENV", "prod")  # default prod

#     # ---------- Session / Cookie configuration ----------
#     app.config["SESSION_COOKIE_NAME"] = "elicita_session"
#     app.config["SESSION_COOKIE_HTTPONLY"] = True
#     app.config["SESSION_COOKIE_PATH"] = "/"

#     if APP_ENV == "dev":
#         # ✅ Dev Mode (localhost or IP without HTTPS)
#         app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
#         app.config["SESSION_COOKIE_SECURE"] = False
#         print("✅ DEV MODE: Cookies set to Lax & Secure=False")
#     else:
#         # 🔐 Prod Mode (HTTPS domain)
#         app.config["SESSION_COOKIE_SAMESITE"] = "None"
#         app.config["SESSION_COOKIE_SECURE"] = True
#         # If you have a domain, uncomment and add here:
#         # app.config["SESSION_COOKIE_DOMAIN"] = ".datasolve-analytics.net"
#         print("🔐 PROD MODE: Cookies set to SameSite=None & Secure=True")
#     # -----------------------------------------------------

#     # Respect X-Forwarded-* headers when behind a proxy / load balancer
#     app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

#     # Secret key for session signing
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
#             "http://127.0.0.1:5173",
#             # Add your new frontend URLs if required
#             # "https://your-frontend.domain",
#         ],
#         supports_credentials=True,
#     )

#     # ---------- Initialize DB and register blueprints ----------
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

#     # ---------- Error handlers ----------
#     @app.errorhandler(404)
#     def not_found_error(error):
#         return jsonify({"success": False, "message": "The requested resource was not found."}), 404

#     @app.errorhandler(500)
#     def internal_error(error):
#         db.session.rollback()
#         return jsonify({"success": False, "message": "An internal server error occurred."}), 500

#     return app


# if __name__ == "__main__":
#     # Set APP_ENV=dev while running locally
#     # Example:  export APP_ENV=dev   OR   set APP_ENV=dev
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

    # If your frontend & API are on subdomains of the same parent, set this:
    # e.g. SESSION_COOKIE_DOMAIN=".datasolve-analytics.net"
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
    host = os.getenv("DB_HOST", "34.93.75.171")
    dbname = os.getenv("DB_NAME", "Elicita_V2")

    app.config["SQLALCHEMY_DATABASE_URI"] = (
        f"mysql+pymysql://{user}:{quote_plus(pwd)}@{host}:3306/{dbname}?charset=utf8mb4"
    )
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


if __name__ == "__main__":
    # Example local:
    #   set APP_ENV=dev
    #   set FRONTEND_ORIGINS=http://localhost:5173
    app = create_app()
    app.run(host="0.0.0.0", port=3070, debug=True)
