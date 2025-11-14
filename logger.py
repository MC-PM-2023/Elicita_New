# # logger.py
# from datetime import datetime, timezone
# from sqlalchemy import text
# from flask import current_app
# from db_config import db

# def _parse_login_time_str(s: str):
#     """
#     session['login_time'] is a string like "%Y-%m-%d %H:%M:%S%z".
#     Convert to naive UTC datetime for MySQL DATETIME column.
#     """
#     if not s:
#         return None
#     try:
#         dt = datetime.strptime(s, "%Y-%m-%d %H:%M:%S%z")
#         return dt.astimezone(timezone.utc).replace(tzinfo=None)
#     except Exception:
#         return None

# def write_log_row(
#     *,
#     name: str = "Anonymous",
#     email: str = "Unknown",
#     date_str: str = None,        # "YYYY-MM-DD"
#     time_str: str = None,        # "HH:MM:SS"
#     login_time_str: str = None,  # parse to DATETIME
#     keyword: str = None,
#     tables_searched: str = None,
#     columns_searched: str = None,
#     fetching_time: float = None,
#     status: str = None,
# ):
#     """
#     Inserts one row into Elicita_V2.log using the primary SQLAlchemy engine.
#     """
#     login_dt = _parse_login_time_str(login_time_str)

#     sql = text("""
#         INSERT INTO `Elicita_V2`.`log`
#         (name, email, date, time, login_time, keyword, tables_searched, columns_searched, fetching_time, status)
#         VALUES
#         (:name, :email, :datev, :timev, :login_time, :keyword, :tables_searched, :columns_searched, :fetching_time, :status)
#     """)

#     params = {
#         "name": name,
#         "email": email,
#         "datev": date_str,
#         "timev": time_str,
#         "login_time": login_dt,
#         "keyword": keyword,
#         "tables_searched": tables_searched,
#         "columns_searched": columns_searched,
#         "fetching_time": fetching_time,
#         "status": status,
#     }
#     try:
#         with db.engine.begin() as conn:
#             conn.execute(sql, params)
#     except Exception as e:
#         current_app.logger.warning(f"[write_log_row] failed: {e}")








# logger.py
from datetime import datetime, timezone
from sqlalchemy import text
from flask import current_app
from db_config import db
import pytz

# Use IST everywhere for log storage
IST = pytz.timezone("Asia/Kolkata")

def _parse_login_time_str(s: str):
    """
    session['login_time'] is stored as "%Y-%m-%d %H:%M:%S%z" (UTC).
    Convert it to naive IST datetime so DB shows consistent India local time.
    """
    if not s:
        return None
    try:
        dt = datetime.strptime(s, "%Y-%m-%d %H:%M:%S%z")     # aware (UTC)
        dt_ist = dt.astimezone(IST)                          # convert to IST
        return dt_ist.replace(tzinfo=None)                   # naive for MySQL DATETIME
    except Exception:
        return None

def write_log_row(
    *,
    name: str = "Anonymous",
    email: str = "Unknown",
    date_str: str = None,        # "YYYY-MM-DD" (already IST from caller)
    time_str: str = None,        # "HH:MM:SS"   (already IST from caller)
    login_time_str: str = None,  # session string; parsed & converted to IST here
    keyword: str = None,
    tables_searched: str = None,
    columns_searched: str = None,
    fetching_time: float = None,
    status: str = None,
):
    """
    Inserts one row into Elicita_V2.log using the primary SQLAlchemy engine.
    All times are stored in IST (naive) for consistency in reports.
    """
    login_dt_ist = _parse_login_time_str(login_time_str)

    sql = text("""
        INSERT INTO `Elicita_V2`.`log`
        (name, email, date, time, login_time, keyword, tables_searched, columns_searched, fetching_time, status)
        VALUES
        (:name, :email, :datev, :timev, :login_time, :keyword, :tables_searched, :columns_searched, :fetching_time, :status)
    """)

    params = {
        "name": name,
        "email": email,
        "datev": date_str,
        "timev": time_str,
        "login_time": login_dt_ist,  # DATETIME (IST) or None
        "keyword": keyword,
        "tables_searched": tables_searched,
        "columns_searched": columns_searched,
        "fetching_time": fetching_time,
        "status": status,
    }
    try:
        with db.engine.begin() as conn:
            conn.execute(sql, params)
    except Exception as e:
        current_app.logger.warning(f"[write_log_row] failed: {e}")

