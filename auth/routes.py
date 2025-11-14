# # from flask import Blueprint, request, jsonify, session, current_app
# # from werkzeug.security import generate_password_hash, check_password_hash
# # from datetime import datetime, timedelta, timezone
# # from .models import Elicita_User_Profiles
# # from db_config import db
# # from .models import User
# # import os, random, ssl
# # from datetime import datetime, timezone


# # # ---------------- JWT (optional PyJWT) ----------------
# # try:
# #     import jwt
# # except ImportError:
# #     jwt = None

# # auth_bp = Blueprint("auth", __name__)

# # # ---------------- CONFIG ----------------
# # SUPER_ADMIN_EMAIL = "apps.admin@datasolve-analytics.com"
# # APP_DOMAIN        = "datasolve-analytics.com"

# # AUTH_SECRET = os.getenv("AUTH_JWT_SECRET", "very-strong-secret-change-me")
# # AUTH_ALGO   = "HS256"

# # # OTP timings
# # OTP_LOGIN_WINDOW_MIN  = 10           # minutes
# # SESSION_VALIDITY_DAYS = 7            # weekly OTP

# # # SMTP (use env in production)
# # SMTP_HOST = os.getenv("SMTP_HOST", "cp-ht-9.webhostbox.net")
# # SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
# # SMTP_USER = os.getenv("SMTP_USER", "apps.admin@datasolve-analytics.com")
# # SMTP_PASS = os.getenv("SMTP_PASS", "datasolve@2025")
# # SENDER_EMAIL = os.getenv("SENDER_EMAIL", "apps.admin@datasolve-analytics.com")


# # # ---------------- HELPERS ----------------
# # def utcnow_naive() -> datetime:
# #     """
# #     Current UTC time as naive datetime (no tzinfo).
# #     Store these in MySQL DATETIME to avoid tz confusion.
# #     """
# #     return datetime.utcnow().replace(tzinfo=None)

# # def to_naive_utc(dt):
# #     """Convert any datetime (aware or naive) to naive UTC."""
# #     if dt is None:
# #         return None
# #     if dt.tzinfo is None:
# #         return dt
# #     return dt.astimezone(timezone.utc).replace(tzinfo=None)

# # def is_past(dt) -> bool:
# #     """Safe expired check for both naive/aware datetimes vs now (naive UTC)."""
# #     if dt is None:
# #         return False
# #     return to_naive_utc(dt) <= utcnow_naive()

# # def generate_otp() -> str:
# #     return f"{random.randint(100000, 999999)}"

# # def role_permissions(role: str) -> dict:
# #     role = (role or "").lower()
# #     if role == "super admin":
# #         return {"viewData": True, "addAssignee": True, "editAssignee": True, "manageRoles": True}
# #     if role == "admin":
# #         return {"viewData": True, "addAssignee": True, "editAssignee": True, "manageRoles": False}
# #     return {"viewData": True, "addAssignee": False, "editAssignee": False, "manageRoles": False}

# # def pretty_role(role: str) -> str:
# #     return {"super admin": "superadmin", "admin": "admin", "user": "User"}.get((role or "").lower(), "User")

# # def jwt_exp_ts(days: int = SESSION_VALIDITY_DAYS) -> int:
# #     """UNIX timestamp for JWT exp, computed in aware UTC."""
# #     return int((datetime.now(timezone.utc) + timedelta(days=days)).timestamp())

# # def sign_jwt(payload: dict) -> str:
# #     # fall back to dev-token if PyJWT not installed
# #     if jwt is None:
# #         return f"dev-token::{payload.get('email','')}::{int(datetime.now(timezone.utc).timestamp())}"
# #     return jwt.encode(payload, AUTH_SECRET, algorithm=AUTH_ALGO)

# # def decode_jwt(token: str):
# #     if jwt is None:
# #         return None
# #     try:
# #         return jwt.decode(token, AUTH_SECRET, algorithms=[AUTH_ALGO])
# #     except Exception:
# #         return None

# # def get_current_user_from_request():
# #     authz = request.headers.get("Authorization", "")
# #     if authz.startswith("Bearer "):
# #         token = authz.split(" ", 1)[1].strip()
# #         data = decode_jwt(token)
# #         if data and "email" in data:
# #             return User.query.filter_by(email=data["email"]).first()
# #     uid = session.get("user_id")
# #     if uid:
# #         return User.query.get(uid)
# #     return None

# # def send_email(to_email: str, otp: str):
# #     import smtplib
# #     subject = "Your OTP Code"
# #     body = f"Your OTP code is {otp}"
# #     message = f"Subject: {subject}\nFrom: {SENDER_EMAIL}\nTo: {to_email}\n\n{body}"
# #     context = ssl.create_default_context()
# #     with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
# #         server.starttls(context=context)
# #         server.login(SMTP_USER, SMTP_PASS)
# #         server.sendmail(SENDER_EMAIL, to_email, message)

# # def ok(message, data=None, code=200):
# #     p = {"success": True, "message": message}
# #     if data is not None:
# #         p["data"] = data
# #     return jsonify(p), code

# # def err(message, code=400):
# #     return jsonify({"success": False, "message": message}), code


# # # ---------------- ROUTES ----------------

# # # 7. Signup
# # # POST /api/auth/signup
# # @auth_bp.route("/signup", methods=["POST"])
# # def signup():
# #     data = request.get_json(silent=True) or {}
# #     first = (data.get("firstname") or "").strip()
# #     last  = (data.get("lastname") or "").strip()
# #     email = (data.get("email") or "").strip().lower()
# #     pw    = data.get("password") or ""
# #     cpw   = data.get("confirmpassword") or ""

# #     if not (first and last and email and pw and cpw):
# #         return err("All fields are required", 400)
# #     if pw != cpw:
# #         return err("Password and confirm password do not match", 400)
# #     if not email.endswith(f"@{APP_DOMAIN}"):
# #         return err(f"Only {APP_DOMAIN} emails are allowed", 400)
# #     if User.query.filter_by(email=email).first():
# #         return err("Email is already registered", 409)

# #     role = "super admin" if email == SUPER_ADMIN_EMAIL else "user"
# #     hashed = generate_password_hash(pw)
# #     otp = generate_otp()

# #     u = User(
# #         first_name=first,
# #         last_name=last,
# #         email=email,
# #         password=hashed,
# #         role=role,
# #         is_verified=False,
# #         otp=otp,
# #         expires_at=utcnow_naive() + timedelta(minutes=OTP_LOGIN_WINDOW_MIN),  # OTP valid for 10 mins
# #         created_at=utcnow_naive(),
# #     )
# #     db.session.add(u)
# #     db.session.commit()

# #     try:
# #         send_email(email, otp)
# #     except Exception as e:
# #         current_app.logger.warning(f"SMTP send failed for {email}: {e}")

# #     # EXACT schema per your example
# #     return jsonify({
# #         "success": True,
# #         "message": f"Signup is successful, OTP sent to {email}",
# #         "data": {"userId": u.id, "email": u.email}
# #     }), 201


# # # 8. Verify OTP
# # # POST /api/auth/verifyotp
# # @auth_bp.route("/verifyotp", methods=["POST"])
# # def verifyotp():
# #     data = request.get_json(silent=True) or {}
# #     email = (data.get("email") or "").strip().lower()
# #     otp   = (data.get("otp") or "").strip()

# #     if not (email and otp):
# #         return err("Email and OTP fields are required", 400)

# #     user = User.query.filter_by(email=email).first()
# #     if not user or user.otp != otp:
# #         return err("OTP doesn't match", 400)

# #     # Check short-lived OTP validity (safe against naive/aware)
# #     if is_past(user.expires_at):
# #         return err("OTP expired", 400)

# #     # Success → Mark verified + give 7 days OTP-free login
# #     user.is_verified = True
# #     user.otp_reverify_until = utcnow_naive() + timedelta(days=SESSION_VALIDITY_DAYS)

# #     # Clear short OTP
# #     user.otp = None
# #     user.expires_at = None
# #     db.session.commit()

# #     # If UI expects token immediately, return full
# #     if data.get("return_token"):
# #         token = sign_jwt({
# #             "email": user.email,
# #             "role": user.role,
# #             "exp": jwt_exp_ts(SESSION_VALIDITY_DAYS)
# #         })
# #         perms = role_permissions(user.role)
# #         return jsonify({
# #             "success": True,
# #             "message": "OTP verified, login successful",
# #             "token": token,
# #             "role": pretty_role(user.role),
# #             "permissions": perms
# #         }), 201

# #     return jsonify({
# #         "success": True,
# #         "message": "Email Verification Successful"
# #     }), 201


# # # Resend OTP
# # # POST /api/auth/resend-otp
# # @auth_bp.route("/resend-otp", methods=["POST"])
# # def resend_otp():
# #     data = request.get_json(silent=True) or {}
# #     email = (data.get("email") or "").strip().lower()
# #     if not email:
# #         return err("Email field is required", 400)

# #     user = User.query.filter_by(email=email).first()
# #     if not user:
# #         return err("Email not found", 404)

# #     otp = generate_otp()
# #     user.otp = otp
# #     user.expires_at = utcnow_naive() + timedelta(minutes=OTP_LOGIN_WINDOW_MIN)
# #     db.session.commit()

# #     try:
# #         send_email(email, otp)
# #     except Exception as e:
# #         current_app.logger.warning(f"SMTP send failed for {email}: {e}")

# #     return ok("New OTP sent to your email.", code=200)

# # @auth_bp.route("/login", methods=["POST"])
# # def login():
# #     """
# #     Login flow:
# #     1) Validate email/password.
# #     2) If user not verified -> send OTP for account verification (short expiry).
# #     3) If verified, enforce weekly OTP flow via `otp_reverify_until`:
# #        - If None or past -> send OTP (short expiry), ask to verify (401).
# #        - If inside window -> create session + JWT and return success.
# #     """
# #     data = request.get_json(silent=True) or {}
# #     email = (data.get("email") or "").strip().lower()
# #     password = data.get("password") or ""

# #     if not (email and password):
# #         return err("Email and password fields are required", 400)

# #     user = User.query.filter_by(email=email).first()
# #     if not user or not check_password_hash(user.password, password):
# #         return err("Invalid email or password", 400)

# #     # ---- Optional profile fetch (gracefully empty) ----
# #     profile = Elicita_User_Profiles.query.filter_by(Email_ID=email).first()
# #     image_url = (profile.Image_URL or "") if profile else ""

# #     # ---- 1) First-time account verification via OTP ----
# #     if not getattr(user, "is_verified", False):
# #         # Generate an OTP only if not already issued or already expired
# #         if not user.otp or is_past(user.expires_at):
# #             user.otp = generate_otp()
# #             user.expires_at = utcnow_naive() + timedelta(minutes=OTP_LOGIN_WINDOW_MIN)
# #             db.session.commit()

# #         try:
# #             send_email(user.email, user.otp)
# #         except Exception as e:
# #             current_app.logger.warning(f"[LOGIN] SMTP send failed for {user.email}: {e}")

# #         return err("Please verify your account", 403)

# #     # ---- 2) Weekly OTP enforcement (uses otp_reverify_until, not expires_at) ----
# #     # If the weekly window is missing or has passed, send a short-lived OTP for re-verification.
# #     if (getattr(user, "otp_reverify_until", None) is None) or is_past(user.otp_reverify_until):
# #         user.otp = generate_otp()
# #         user.expires_at = utcnow_naive() + timedelta(minutes=OTP_LOGIN_WINDOW_MIN)  # short OTP validity
# #         db.session.commit()

# #         try:
# #             send_email(user.email, user.otp)
# #         except Exception as e:
# #             current_app.logger.warning(f"[LOGIN] SMTP send failed for {user.email}: {e}")

# #         # Frontend should now call /verifyotp to complete login and extend otp_reverify_until by 7 days.
# #         return err("OTP required, sent to your email", 401)

# #     # ---- 3) Inside weekly OTP-free window → Allow session login ----
# #     session["user_id"] = user.id
# #     session["user_email"] = user.email
# #     session["user_name"] = user.first_name
# #     session["user_role"] = user.role
# #     # Store in UTC for consistency across servers
# #     session["login_time"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S%z")

# #     token = sign_jwt({
# #         "email": user.email,
# #         "role": user.role,
# #         "exp": jwt_exp_ts(SESSION_VALIDITY_DAYS)
# #     })
# #     perms = role_permissions(user.role)

# #     return jsonify({
# #         "success": True,
# #         "message": "Login successful",
# #         "token": token,
# #         "profilelink": image_url,
# #         "firstname": user.first_name or "",
# #         "lastname": user.last_name or "",
# #         "email": user.email,
# #         "role": pretty_role(user.role),
# #         "permissions": perms
# #     }), 200

# # # Logout
# # # POST /api/auth/logout
# # @auth_bp.route("/logout", methods=["POST"])
# # def logout():
# #     session.clear()
# #     return ok("Logout successful")


# # # SuperAdmin Assigns Roles
# # # POST /api/auth/admin/assignrole
# # @auth_bp.route("/admin/assignrole", methods=["POST"])
# # def assign_role():
# #     caller = get_current_user_from_request()
# #     if not caller or caller.email.lower() != SUPER_ADMIN_EMAIL:
# #         return err("Access denied. Only SuperAdmin can assign roles", 403)

# #     data = request.get_json(silent=True) or {}
# #     email = (data.get("email") or "").strip().lower()
# #     role  = (data.get("role") or "").strip().lower()

# #     if not (email and role):
# #         return err("Email and role fields are required", 400)

# #     role_map = {"user": "user", "admin": "admin"}
# #     norm_role = role_map.get(role)
# #     if norm_role is None:
# #         return err("Role must be 'user' or 'admin'", 400)

# #     u = User.query.filter_by(email=email).first()
# #     if not u:
# #         return err("User with this email not found", 404)

# #     u.role = norm_role
# #     db.session.commit()

# #     return jsonify({
# #         "success": True,
# #         "message": "Role updated successfully",
# #         "data": {"userId": u.id, "email": u.email, "role": pretty_role(u.role)}
# #     }), 200


# # # Reset Password (with OTP from forgotpassword)
# # # POST /api/auth/resetpassword
# # @auth_bp.route("/resetpassword", methods=["POST"])
# # def reset_password():
# #     data = request.get_json(silent=True) or {}
# #     email = (data.get("email") or "").strip().lower()
# #     otp   = (data.get("otp") or "").strip()
# #     newpw = data.get("newpassword") or ""
# #     if not (email and otp and newpw):
# #         return err("Email, OTP and new_password are required", 400)

# #     user = User.query.filter_by(email=email).first()
# #     if not user or user.otp != otp:
# #         return err("Invalid OTP", 400)

# #     if is_past(user.expires_at):
# #         return err("OTP expired", 400)

# #     user.password = generate_password_hash(newpw)
# #     user.otp = None
# #     db.session.commit()
# #     return ok("Password reset successful")


# # # Forgot Password (send OTP)
# # # POST /api/auth/forgotpassword
# # @auth_bp.route("/forgotpassword", methods=["POST"])
# # def forgot_password():
# #     data = request.get_json(silent=True) or {}
# #     email = (data.get("email") or "").strip().lower()
# #     if not email:
# #         return err("Email is required", 400)

# #     user = User.query.filter_by(email=email).first()
# #     if not user:
# #         return err("Email not found", 404)

# #     otp = generate_otp()
# #     user.otp = otp
# #     user.expires_at = utcnow_naive() + timedelta(minutes=OTP_LOGIN_WINDOW_MIN)
# #     db.session.commit()

# #     try:
# #         send_email(email, otp)
# #     except Exception as e:
# #         current_app.logger.warning(f"SMTP send failed for {email}: {e}")

# #     return ok("OTP sent for password reset")









# # auth/routes.py
# from flask import Blueprint, request, jsonify, session, current_app
# from werkzeug.security import generate_password_hash, check_password_hash
# from datetime import datetime, timedelta, timezone
# import os, random, ssl

# from db_config import db
# from .models import User, Elicita_User_Profiles

# # ---------------- JWT (optional PyJWT) ----------------
# try:
#     import jwt
# except ImportError:
#     jwt = None

# auth_bp = Blueprint("auth", __name__)

# # ---------------- CONFIG ----------------
# SUPER_ADMIN_EMAIL = "apps.admin@datasolve-analytics.com"
# APP_DOMAIN        = "datasolve-analytics.com"

# AUTH_SECRET = os.getenv("AUTH_JWT_SECRET", "very-strong-secret-change-me")
# AUTH_ALGO   = "HS256"

# # OTP timings
# OTP_LOGIN_WINDOW_MIN  = 10           # minutes
# SESSION_VALIDITY_DAYS = 7            # weekly OTP

# # SMTP (use env in production)
# SMTP_HOST = os.getenv("SMTP_HOST", "cp-ht-9.webhostbox.net")
# SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
# SMTP_USER = os.getenv("SMTP_USER", "apps.admin@datasolve-analytics.com")
# SMTP_PASS = os.getenv("SMTP_PASS", "")
# SENDER_EMAIL = os.getenv("SENDER_EMAIL", "apps.admin@datasolve-analytics.com")

# # ---------------- HELPERS ----------------
# def utcnow_naive():
#     return datetime.utcnow().replace(tzinfo=None)

# def to_naive_utc(dt):
#     if dt is None:
#         return None
#     if dt.tzinfo is None:
#         return dt
#     return dt.astimezone(timezone.utc).replace(tzinfo=None)

# def is_past(dt) -> bool:
#     if dt is None:
#         return False
#     return to_naive_utc(dt) <= utcnow_naive()

# def generate_otp() -> str:
#     return f"{random.randint(100000, 999999)}"

# def role_permissions(role: str) -> dict:
#     role = (role or "").lower()
#     if role == "super admin":
#         return {"viewData": True, "addAssignee": True, "editAssignee": True, "manageRoles": True}
#     if role == "admin":
#         return {"viewData": True, "addAssignee": True, "editAssignee": True, "manageRoles": False}
#     return {"viewData": True, "addAssignee": False, "editAssignee": False, "manageRoles": False}

# def pretty_role(role: str) -> str:
#     return {"super admin": "superadmin", "admin": "admin", "user": "User"}.get((role or "").lower(), "User")

# def jwt_exp_ts(days: int = SESSION_VALIDITY_DAYS) -> int:
#     return int((datetime.now(timezone.utc) + timedelta(days=days)).timestamp())

# def sign_jwt(payload: dict) -> str:
#     if jwt is None:
#         return f"dev-token::{payload.get('email','')}::{int(datetime.now(timezone.utc).timestamp())}"
#     return jwt.encode(payload, AUTH_SECRET, algorithm=AUTH_ALGO)

# def decode_jwt(token: str):
#     if jwt is None:
#         return None
#     try:
#         return jwt.decode(token, AUTH_SECRET, algorithms=[AUTH_ALGO])
#     except Exception:
#         return None

# def get_current_user_from_request():
#     authz = request.headers.get("Authorization", "")
#     if authz.startswith("Bearer "):
#         token = authz.split(" ", 1)[1].strip()
#         data = decode_jwt(token)
#         if data and "email" in data:
#             return User.query.filter_by(email=data["email"]).first()
#     uid = session.get("user_id")
#     if uid:
#         return User.query.get(uid)
#     return None

# def send_email(to_email: str, otp: str):
#     import smtplib
#     subject = "Your OTP Code"
#     body = f"Your OTP code is {otp}"
#     message = f"Subject: {subject}\nFrom: {SENDER_EMAIL}\nTo: {to_email}\n\n{body}"
#     context = ssl.create_default_context()
#     with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
#         server.starttls(context=context)
#         if SMTP_USER and SMTP_PASS:
#             server.login(SMTP_USER, SMTP_PASS)
#         server.sendmail(SENDER_EMAIL, to_email, message)

# def ok(message, data=None, code=200):
#     p = {"success": True, "message": message}
#     if data is not None:
#         p["data"] = data
#     return jsonify(p), code

# def err(message, code=400):
#     return jsonify({"success": False, "message": message}), code

# # ---------------- ROUTES ----------------

# @auth_bp.route("/signup", methods=["POST"])
# def signup():
#     data = request.get_json(silent=True) or {}
#     first = (data.get("firstname") or "").strip()
#     last  = (data.get("lastname") or "").strip()
#     email = (data.get("email") or "").strip().lower()
#     pw    = data.get("password") or ""
#     cpw   = data.get("confirmpassword") or ""

#     if not (first and last and email and pw and cpw):
#         return err("All fields are required", 400)
#     if pw != cpw:
#         return err("Password and confirm password do not match", 400)
#     if not email.endswith(f"@{APP_DOMAIN}"):
#         return err(f"Only {APP_DOMAIN} emails are allowed", 400)
#     if User.query.filter_by(email=email).first():
#         return err("Email is already registered", 409)

#     role = "super admin" if email == SUPER_ADMIN_EMAIL else "user"
#     hashed = generate_password_hash(pw)
#     otp = generate_otp()

#     u = User(
#         first_name=first,
#         last_name=last,
#         email=email,
#         password=hashed,
#         role=role,
#         is_verified=False,
#         otp=otp,
#         expires_at=utcnow_naive() + timedelta(minutes=OTP_LOGIN_WINDOW_MIN),
#         created_at=utcnow_naive(),
#     )
#     db.session.add(u)
#     db.session.commit()

#     try:
#         send_email(email, otp)
#     except Exception as e:
#         current_app.logger.warning(f"SMTP send failed for {email}: {e}")

#     return jsonify({
#         "success": True,
#         "message": f"Signup is successful, OTP sent to {email}",
#         "data": {"userId": u.id, "email": u.email}
#     }), 201

# @auth_bp.route("/verifyotp", methods=["POST"])
# def verifyotp():
#     data = request.get_json(silent=True) or {}
#     email = (data.get("email") or "").strip().lower()
#     otp   = (data.get("otp") or "").strip()

#     if not (email and otp):
#         return err("Email and OTP fields are required", 400)

#     user = User.query.filter_by(email=email).first()
#     if not user or user.otp != otp:
#         return err("OTP doesn't match", 400)

#     if is_past(user.expires_at):
#         return err("OTP expired", 400)

#     user.is_verified = True
#     user.otp_reverify_until = utcnow_naive() + timedelta(days=SESSION_VALIDITY_DAYS)
#     user.otp = None
#     user.expires_at = None
#     db.session.commit()

#     if data.get("return_token"):
#         token = sign_jwt({
#             "email": user.email,
#             "role": user.role,
#             "exp": jwt_exp_ts(SESSION_VALIDITY_DAYS)
#         })
#         perms = role_permissions(user.role)
#         return jsonify({
#             "success": True,
#             "message": "OTP verified, login successful",
#             "token": token,
#             "role": pretty_role(user.role),
#             "permissions": perms
#         }), 201

#     return jsonify({"success": True, "message": "Email Verification Successful"}), 201

# @auth_bp.route("/resend-otp", methods=["POST"])
# def resend_otp():
#     data = request.get_json(silent=True) or {}
#     email = (data.get("email") or "").strip().lower()
#     if not email:
#         return err("Email field is required", 400)

#     user = User.query.filter_by(email=email).first()
#     if not user:
#         return err("Email not found", 404)

#     otp = generate_otp()
#     user.otp = otp
#     user.expires_at = utcnow_naive() + timedelta(minutes=OTP_LOGIN_WINDOW_MIN)
#     db.session.commit()

#     try:
#         send_email(email, otp)
#     except Exception as e:
#         current_app.logger.warning(f"SMTP send failed for {email}: {e}")

#     return ok("New OTP sent to your email.", code=200)

# @auth_bp.route("/login", methods=["POST"])
# def login():
#     """
#     Login + weekly OTP enforcement:
#     - If user not verified → send OTP (403).
#     - If weekly window expired → send OTP (401).
#     - Else → create session, return token (200).
#     NOTE: No log writes here by design.
#     """
#     data = request.get_json(silent=True) or {}
#     email = (data.get("email") or "").strip().lower()
#     password = data.get("password") or ""

#     if not (email and password):
#         return err("Email and password fields are required", 400)

#     user = User.query.filter_by(email=email).first()
#     if not user or not check_password_hash(user.password, password):
#         return err("Invalid email or password", 400)

#     profile = Elicita_User_Profiles.query.filter_by(Email_ID=email).first()
#     image_url = (profile.Image_URL or "") if profile else ""

#     if not getattr(user, "is_verified", False):
#         if not user.otp or is_past(user.expires_at):
#             user.otp = generate_otp()
#             user.expires_at = utcnow_naive() + timedelta(minutes=OTP_LOGIN_WINDOW_MIN)
#             db.session.commit()
#         try:
#             send_email(user.email, user.otp)
#         except Exception as e:
#             current_app.logger.warning(f"[LOGIN] SMTP send failed for {user.email}: {e}")
#         return err("Please verify your account", 403)

#     if (getattr(user, "otp_reverify_until", None) is None) or is_past(user.otp_reverify_until):
#         user.otp = generate_otp()
#         user.expires_at = utcnow_naive() + timedelta(minutes=OTP_LOGIN_WINDOW_MIN)
#         db.session.commit()
#         try:
#             send_email(user.email, user.otp)
#         except Exception as e:
#             current_app.logger.warning(f"[LOGIN] SMTP send failed for {user.email}: {e}")
#         return err("OTP required, sent to your email", 401)

#     session["user_id"] = user.id
#     session["user_email"] = user.email
#     session["user_name"] = user.first_name
#     session["user_role"] = user.role
#     session["login_time"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S%z")

#     token = sign_jwt({"email": user.email, "role": user.role, "exp": jwt_exp_ts(SESSION_VALIDITY_DAYS)})
#     perms = role_permissions(user.role)

#     return jsonify({
#         "success": True,
#         "message": "Login successful",
#         "token": token,
#         "profilelink": image_url,
#         "firstname": user.first_name or "",
#         "lastname": user.last_name or "",
#         "email": user.email,
#         "role": pretty_role(user.role),
#         "permissions": perms
#     }), 200

# @auth_bp.route("/logout", methods=["POST"])
# def logout():
#     session.clear()
#     return ok("Logout successful")

# @auth_bp.route("/admin/assignrole", methods=["POST"])
# def assign_role():
#     caller = get_current_user_from_request()
#     if not caller or caller.email.lower() != SUPER_ADMIN_EMAIL:
#         return err("Access denied. Only SuperAdmin can assign roles", 403)

#     data = request.get_json(silent=True) or {}
#     email = (data.get("email") or "").strip().lower()
#     role  = (data.get("role") or "").strip().lower()

#     if not (email and role):
#         return err("Email and role fields are required", 400)

#     role_map = {"user": "user", "admin": "admin"}
#     norm_role = role_map.get(role)
#     if norm_role is None:
#         return err("Role must be 'user' or 'admin'", 400)

#     u = User.query.filter_by(email=email).first()
#     if not u:
#         return err("User with this email not found", 404)

#     u.role = norm_role
#     db.session.commit()

#     return jsonify({
#         "success": True,
#         "message": "Role updated successfully",
#         "data": {"userId": u.id, "email": u.email, "role": pretty_role(u.role)}
#     }), 200

# @auth_bp.route("/resetpassword", methods=["POST"])
# def reset_password():
#     data = request.get_json(silent=True) or {}
#     email = (data.get("email") or "").strip().lower()
#     otp   = (data.get("otp") or "").strip()
#     newpw = data.get("newpassword") or ""
#     if not (email and otp and newpw):
#         return err("Email, OTP and new_password are required", 400)

#     user = User.query.filter_by(email=email).first()
#     if not user or user.otp != otp:
#         return err("Invalid OTP", 400)

#     if is_past(user.expires_at):
#         return err("OTP expired", 400)

#     user.password = generate_password_hash(newpw)
#     user.otp = None
#     db.session.commit()
#     return ok("Password reset successful")

# @auth_bp.route("/forgotpassword", methods=["POST"])
# def forgot_password():
#     data = request.get_json(silent=True) or {}
#     email = (data.get("email") or "").strip().lower()
#     if not email:
#         return err("Email is required", 400)

#     user = User.query.filter_by(email=email).first()
#     if not user:
#         return err("Email not found", 404)

#     otp = generate_otp()
#     user.otp = otp
#     user.expires_at = utcnow_naive() + timedelta(minutes=OTP_LOGIN_WINDOW_MIN)
#     db.session.commit()

#     try:
#         send_email(email, otp)
#     except Exception as e:
#         current_app.logger.warning(f"SMTP send failed for {email}: {e}")

#     return ok("OTP sent for password reset")




















# auth/routes.py
from flask import Blueprint, request, jsonify, session, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
import os, random, ssl

from db_config import db
from .models import User, Elicita_User_Profiles

# ---------------- JWT (optional PyJWT) ----------------
try:
    import jwt
except ImportError:
    jwt = None

auth_bp = Blueprint("auth", __name__)

# ---------------- CONFIG ----------------
SUPER_ADMIN_EMAIL = "apps.admin@datasolve-analytics.com"
APP_DOMAIN        = "datasolve-analytics.com"

AUTH_SECRET = os.getenv("AUTH_JWT_SECRET", "very-strong-secret-change-me")
AUTH_ALGO   = "HS256"

# OTP timings
OTP_LOGIN_WINDOW_MIN  = 10           # minutes
SESSION_VALIDITY_DAYS = 7            # weekly OTP

# SMTP (use env in production)
SMTP_HOST = os.getenv("SMTP_HOST", "cp-ht-9.webhostbox.net")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "apps.admin@datasolve-analytics.com")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "apps.admin@datasolve-analytics.com")

# ---------------- HELPERS ----------------
def utcnow_naive():
    return datetime.utcnow().replace(tzinfo=None)

def to_naive_utc(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt
    return dt.astimezone(timezone.utc).replace(tzinfo=None)

def is_past(dt) -> bool:
    if dt is None:
        return False
    return to_naive_utc(dt) <= utcnow_naive()

def generate_otp() -> str:
    return f"{random.randint(100000, 999999)}"

def role_permissions(role: str) -> dict:
    role = (role or "").lower()
    if role == "super admin":
        return {"viewData": True, "addAssignee": True, "editAssignee": True, "manageRoles": True}
    if role == "admin":
        return {"viewData": True, "addAssignee": True, "editAssignee": True, "manageRoles": False}
    return {"viewData": True, "addAssignee": False, "editAssignee": False, "manageRoles": False}

def pretty_role(role: str) -> str:
    return {"super admin": "superadmin", "admin": "admin", "user": "User"}.get((role or "").lower(), "User")

def jwt_exp_ts(days: int = SESSION_VALIDITY_DAYS) -> int:
    return int((datetime.now(timezone.utc) + timedelta(days=days)).timestamp())

def sign_jwt(payload: dict) -> str:
    if jwt is None:
        return f"dev-token::{payload.get('email','')}::{int(datetime.now(timezone.utc).timestamp())}"
    return jwt.encode(payload, AUTH_SECRET, algorithm=AUTH_ALGO)

def decode_jwt(token: str):
    if jwt is None:
        return None
    try:
        return jwt.decode(token, AUTH_SECRET, algorithms=[AUTH_ALGO])
    except Exception:
        return None

def get_current_user_from_request():
    authz = request.headers.get("Authorization", "")
    if authz.startswith("Bearer "):
        token = authz.split(" ", 1)[1].strip()
        data = decode_jwt(token)
        if data and "email" in data:
            return User.query.filter_by(email=data["email"]).first()
    uid = session.get("user_id")
    if uid:
        return User.query.get(uid)
    return None

def send_email(to_email: str, otp: str):
    import smtplib
    subject = "Your OTP Code"
    body = f"Your OTP code is {otp}"
    message = f"Subject: {subject}\nFrom: {SENDER_EMAIL}\nTo: {to_email}\n\n{body}"
    context = ssl.create_default_context()
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls(context=context)
        if SMTP_USER and SMTP_PASS:
            server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SENDER_EMAIL, to_email, message)

def ok(message, data=None, code=200):
    p = {"success": True, "message": message}
    if data is not None:
        p["data"] = data
    return jsonify(p), code

def err(message, code=400):
    return jsonify({"success": False, "message": message}), code

# ---------------- ROUTES ----------------

@auth_bp.route("/signup", methods=["POST"])
def signup():
    data = request.get_json(silent=True) or {}
    first = (data.get("firstname") or "").strip()
    last  = (data.get("lastname") or "").strip()
    email = (data.get("email") or "").strip().lower()
    pw    = data.get("password") or ""
    cpw   = data.get("confirmpassword") or ""

    if not (first and last and email and pw and cpw):
        return err("All fields are required", 400)
    if pw != cpw:
        return err("Password and confirm password do not match", 400)
    if not email.endswith(f"@{APP_DOMAIN}"):
        return err(f"Only {APP_DOMAIN} emails are allowed", 400)
    if User.query.filter_by(email=email).first():
        return err("Email is already registered", 409)

    role = "super admin" if email == SUPER_ADMIN_EMAIL else "user"
    hashed = generate_password_hash(pw)
    otp = generate_otp()

    u = User(
        first_name=first,
        last_name=last,
        email=email,
        password=hashed,
        role=role,
        is_verified=False,
        otp=otp,
        expires_at=utcnow_naive() + timedelta(minutes=OTP_LOGIN_WINDOW_MIN),
        created_at=utcnow_naive(),
    )
    db.session.add(u)
    db.session.commit()

    try:
        send_email(email, otp)
    except Exception as e:
        current_app.logger.warning(f"SMTP send failed for {email}: {e}")

    return jsonify({
        "success": True,
        "message": f"Signup is successful, OTP sent to {email}",
        "data": {"userId": u.id, "email": u.email}
    }), 201

@auth_bp.route("/verifyotp", methods=["POST"])
def verifyotp():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    otp   = (data.get("otp") or "").strip()

    if not (email and otp):
        return err("Email and OTP fields are required", 400)

    user = User.query.filter_by(email=email).first()
    if not user or user.otp != otp:
        return err("OTP doesn't match", 400)

    if is_past(user.expires_at):
        return err("OTP expired", 400)

    user.is_verified = True
    user.otp_reverify_until = utcnow_naive() + timedelta(days=SESSION_VALIDITY_DAYS)
    user.otp = None
    user.expires_at = None
    db.session.commit()

    if data.get("return_token"):
        token = sign_jwt({
            "email": user.email,
            "role": user.role,
            "exp": jwt_exp_ts(SESSION_VALIDITY_DAYS)
        })
        perms = role_permissions(user.role)
        return jsonify({
            "success": True,
            "message": "OTP verified, login successful",
            "token": token,
            "role": pretty_role(user.role),
            "permissions": perms
        }), 201

    return jsonify({"success": True, "message": "Email Verification Successful"}), 201

@auth_bp.route("/resend-otp", methods=["POST"])
def resend_otp():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return err("Email field is required", 400)

    user = User.query.filter_by(email=email).first()
    if not user:
        return err("Email not found", 404)

    otp = generate_otp()
    user.otp = otp
    user.expires_at = utcnow_naive() + timedelta(minutes=OTP_LOGIN_WINDOW_MIN)
    db.session.commit()

    try:
        send_email(email, otp)
    except Exception as e:
        current_app.logger.warning(f"SMTP send failed for {email}: {e}")

    return ok("New OTP sent to your email.", code=200)

@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Weekly OTP enforcement. (No log writes here; logs only for searches.)
    """
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not (email and password):
        return err("Email and password fields are required", 400)

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        return err("Invalid email or password", 400)

    profile = Elicita_User_Profiles.query.filter_by(Email_ID=email).first()
    image_url = (profile.Image_URL or "") if profile else ""

    if not getattr(user, "is_verified", False):
        if not user.otp or is_past(user.expires_at):
            user.otp = generate_otp()
            user.expires_at = utcnow_naive() + timedelta(minutes=OTP_LOGIN_WINDOW_MIN)
            db.session.commit()
        try:
            send_email(user.email, user.otp)
        except Exception as e:
            current_app.logger.warning(f"[LOGIN] SMTP send failed for {user.email}: {e}")
        return err("Please verify your account", 403)

    if (getattr(user, "otp_reverify_until", None) is None) or is_past(user.otp_reverify_until):
        user.otp = generate_otp()
        user.expires_at = utcnow_naive() + timedelta(minutes=OTP_LOGIN_WINDOW_MIN)
        db.session.commit()
        try:
            send_email(user.email, user.otp)
        except Exception as e:
            current_app.logger.warning(f"[LOGIN] SMTP send failed for {user.email}: {e}")
        return err("OTP required, sent to your email", 401)

    session["user_id"] = user.id
    session["user_email"] = user.email
    session["user_name"] = user.first_name
    session["user_role"] = user.role
    session["login_time"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S%z")

    token = sign_jwt({"email": user.email, "role": user.role, "exp": jwt_exp_ts(SESSION_VALIDITY_DAYS)})
    perms = role_permissions(user.role)

    return jsonify({
        "success": True,
        "message": "Login successful",
        "token": token,
        "profilelink": image_url,
        "firstname": user.first_name or "",
        "lastname": user.last_name or "",
        "email": user.email,
        "role": pretty_role(user.role),
        "permissions": perms
    }), 200

@auth_bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return ok("Logout successful")

@auth_bp.route("/admin/assignrole", methods=["POST"])
def assign_role():
    caller = get_current_user_from_request()
    if not caller or caller.email.lower() != SUPER_ADMIN_EMAIL:
        return err("Access denied. Only SuperAdmin can assign roles", 403)

    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    role  = (data.get("role") or "").strip().lower()

    if not (email and role):
        return err("Email and role fields are required", 400)

    role_map = {"user": "user", "admin": "admin"}
    norm_role = role_map.get(role)
    if norm_role is None:
        return err("Role must be 'user' or 'admin'", 400)

    u = User.query.filter_by(email=email).first()
    if not u:
        return err("User with this email not found", 404)

    u.role = norm_role
    db.session.commit()

    return jsonify({
        "success": True,
        "message": "Role updated successfully",
        "data": {"userId": u.id, "email": u.email, "role": pretty_role(u.role)}
    }), 200

@auth_bp.route("/resetpassword", methods=["POST"])
def reset_password():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    otp   = (data.get("otp") or "").strip()
    newpw = data.get("newpassword") or ""
    if not (email and otp and newpw):
        return err("Email, OTP and new_password are required", 400)

    user = User.query.filter_by(email=email).first()
    if not user or user.otp != otp:
        return err("Invalid OTP", 400)

    if is_past(user.expires_at):
        return err("OTP expired", 400)

    user.password = generate_password_hash(newpw)
    user.otp = None
    db.session.commit()
    return ok("Password reset successful")

@auth_bp.route("/forgotpassword", methods=["POST"])
def forgot_password():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return err("Email is required", 400)

    user = User.query.filter_by(email=email).first()
    if not user:
        return err("Email not found", 404)

    otp = generate_otp()
    user.otp = otp
    user.expires_at = utcnow_naive() + timedelta(minutes=OTP_LOGIN_WINDOW_MIN)
    db.session.commit()

    try:
        send_email(email, otp)
    except Exception as e:
        current_app.logger.warning(f"SMTP send failed for {email}: {e}")

    return ok("OTP sent for password reset")
