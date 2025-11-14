# # log.py (Full updated code)
# from flask import Blueprint, jsonify
# from db_config import db 
# # Assuming your Log model is now correctly defined in auth/models.py
# from auth.models import Log 

# # Define the Blueprint
# log_bp = Blueprint('logs', __name__)

# @log_bp.route('/api/logs', methods=['GET'])
# def get_activity_logs():
#     """
#     Fetches all user activity logs from the database (the 'log' table) 
#     and returns them as a JSON API response.
#     """
#     try:
#         # Query all log entries. Ordering by id descending for latest logs first.
#         logs = Log.query.order_by(Log.id.desc()).all()
        
#         # Convert the list of Log objects to a list of dictionaries using the to_dict method
#         # The to_dict method now safely handles the timedelta object
#         log_data = [log.to_dict() for log in logs]
        
#         # Return the data as a JSON response
#         return jsonify({
#             "success": True,
#             "data": log_data
#         }), 200
        
#     except Exception as e:
#         # Log the error for server-side debugging
#         # This will now clearly show if a new error occurs (e.g., connection, unknown column)
#         print(f"Error fetching logs: {e}") 
#         # Rollback in case the error was during a database transaction
#         db.session.rollback() 
#         return jsonify({
#             "success": False, 
#             "message": "An internal error occurred while fetching log data."
#         }), 500











# log.py
# log.py
from flask import Blueprint, jsonify, request, current_app
from sqlalchemy import text
from db_config import db
from datetime import datetime, date, time, timedelta
from decimal import Decimal

log_bp = Blueprint("log_api", __name__)

# ---------- format helpers ----------

def _fmt_date(v):
    if v is None:
        return ""
    if isinstance(v, (datetime,)):
        return v.date().strftime("%Y-%m-%d")
    if isinstance(v, date):
        return v.strftime("%Y-%m-%d")
    return str(v)

def _fmt_time(v):
    """
    MySQL TIME may arrive as datetime.time (pymysql) or datetime.timedelta (mysqlclient).
    Normalize to HH:MM:SS.
    """
    if v is None:
        return ""
    if isinstance(v, time):
        return v.strftime("%H:%M:%S")
    if isinstance(v, timedelta):
        total = int(v.total_seconds())
        if total < 0:
            total = -total
        h = (total // 3600) % 24
        m = (total % 3600) // 60
        s = total % 60
        return f"{h:02d}:{m:02d}:{s:02d}"
    # fallback
    return str(v)

def _fmt_dt(v):
    if v is None:
        return ""
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%d %H:%M:%S")
    # sometimes DATETIME may come as string already
    return str(v)

def _to_float(v, default=0.0):
    if v is None:
        return default
    if isinstance(v, (float, int)):
        return float(v)
    if isinstance(v, Decimal):
        return float(v)
    try:
        return float(v)
    except Exception:
        return default

def _row_to_dict(row):
    d = dict(row._mapping)

    d["date"]        = _fmt_date(d.get("date"))
    d["time"]        = _fmt_time(d.get("time"))
    d["login_time"]  = _fmt_dt(d.get("login_time"))
    d["fetching_time"] = _to_float(d.get("fetching_time"), 0.0)

    # ensure strings
    for k in ("name", "email", "keyword", "tables_searched", "columns_searched", "status"):
        if d.get(k) is None:
            d[k] = ""

    return d

@log_bp.route("/api/logs", methods=["GET"])
def get_logs():
    """
    Returns logs from Elicita_V2.log as JSON.
    Optional query params:
      - limit (default 200, max 1000)
      - offset (default 0)
      - q (search in multiple columns)
    """
    try:
        # pagination
        try:
            limit = int(request.args.get("limit", 200))
        except ValueError:
            limit = 200
        limit = max(1, min(limit, 1000))

        try:
            offset = int(request.args.get("offset", 0))
        except ValueError:
            offset = 0
        offset = max(0, offset)

        q = (request.args.get("q") or "").strip()

        base_sql = """
            SELECT
                id, name, email, date, time, login_time,
                keyword, tables_searched, columns_searched,
                fetching_time, status
            FROM `Elicita_V2`.`log`
        """

        where_sql = ""
        params = {"lim": limit, "off": offset}

        if q:
            where_sql = """
                WHERE
                    (name LIKE :p OR email LIKE :p OR keyword LIKE :p
                     OR tables_searched LIKE :p OR columns_searched LIKE :p
                     OR status LIKE :p)
            """
            params["p"] = f"%{q}%"

        order_sql = " ORDER BY id DESC LIMIT :lim OFFSET :off"
        sql = text(base_sql + where_sql + order_sql)

        with db.engine.connect() as conn:
            rows = conn.execute(sql, params).fetchall()

        data = [_row_to_dict(r) for r in rows]

        # total count (for UI pagination)
        if q:
            count_sql = text("""
                SELECT COUNT(*) AS c FROM `Elicita_V2`.`log`
                WHERE
                    (name LIKE :p OR email LIKE :p OR keyword LIKE :p
                     OR tables_searched LIKE :p OR columns_searched LIKE :p
                     OR status LIKE :p)
            """)
            with db.engine.connect() as conn:
                total = conn.execute(count_sql, {"p": f"%{q}%"}).scalar() or 0
        else:
            with db.engine.connect() as conn:
                total = conn.execute(text("SELECT COUNT(*) FROM `Elicita_V2`.`log`")).scalar() or 0

        return jsonify({
            "success": True,
            "total": int(total),
            "limit": limit,
            "offset": offset,
            "data": data
        }), 200

    except Exception as e:
        current_app.logger.exception(f"[GET /api/logs] failed: {e}")
        return jsonify({
            "success": False,
            "message": "An internal error occurred while fetching log data."
        }), 500

