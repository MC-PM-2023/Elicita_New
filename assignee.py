from flask import Blueprint, request, jsonify, session
from sqlalchemy import text
from db_config import db
import os, re

try:
    import jwt
except ImportError:
    jwt = None

api_bp = Blueprint("assignee", __name__, url_prefix="/api")
TBL = "`Elicita_V2`.`Assignee_Table`"

AUTH_SECRET = os.getenv("AUTH_JWT_SECRET", "very-strong-secret-change-me")
AUTH_ALGO   = "HS256"

# ---------------- Helpers ----------------
def _json(success: bool, message: str, data=None, code=200):
    payload = {"success": success, "message": message}
    if data is not None:
        payload["data"] = data
    return jsonify(payload), code

def _get_caller_role():
    authz = request.headers.get("Authorization", "")
    if authz.startswith("Bearer "):
        token = authz.split(" ", 1)[1].strip()
        if jwt:
            try:
                payload = jwt.decode(token, AUTH_SECRET, algorithms=[AUTH_ALGO])
                return (payload.get("role") or "").lower()
            except Exception:
                pass
    return (session.get("user_role") or "").lower()

def _require_admin():
    return _get_caller_role() in ("admin", "super admin")

_url_re = re.compile(r"^(https?://)?([A-Za-z0-9.-]+\.[A-Za-z]{2,})(:[0-9]{1,5})?(/.*)?$")

def _norm_url(u: str | None) -> str | None:
    """Return normalized URL or None (to store NULL)."""
    if not u:
        return None
    u = u.strip()
    if not u:
        return None
    # quick sanity: allow http/https or bare domain; add scheme if missing
    if not _url_re.match(u):
        # if it's something like 'example' (no TLD) -> treat as invalid -> None
        return None
    if not u.lower().startswith(("http://", "https://")):
        u = "http://" + u
    return u[:512]  # safety cap

# ----------------------------------------------------------
# Search Assignee
# POST /api/assignee/assigneedata
# Body: { "column": "Assignee_Name", "input": "vasanth" }
# ----------------------------------------------------------
@api_bp.route("/assignee/assigneedata", methods=["POST"])
def assignee_data():
    data = request.get_json(silent=True) or {}
    column_to_search = (data.get("column") or "").strip()
    search_input     = (data.get("input") or "").strip()

    if not column_to_search or not search_input:
        return _json(False, "Assignee is required", data=[], code=400)

    allowed_columns = ["id", "Assignee_Name", "Product_Category", "Assignee_URL"]
    if column_to_search not in allowed_columns:
        return _json(False, f"Invalid column name '{column_to_search}'. Search is not allowed on this column.", code=400)

    try:
        if column_to_search == "id":
            where_clause = "CAST(id AS CHAR) LIKE :kw"
        else:
            where_clause = f"LOWER(`{column_to_search}`) LIKE LOWER(:kw)"

        sql = text(f"""
            SELECT id, Assignee_Name, Product_Category, Assignee_URL
            FROM {TBL}
            WHERE {where_clause}
            ORDER BY id ASC
        """)
        rows = db.session.execute(sql, {"kw": f"%{search_input}%"}).mappings().all()

        if not rows:
            return _json(False, "No assignee data found", data=[], code=404)

        out = [
            {
                "id": r["id"],
                "assigneename": r["Assignee_Name"],
                "productcategory": r["Product_Category"],
                "assigneeurl": r["Assignee_URL"],
            }
            for r in rows
        ]
        return _json(True, "assignee data retrieved successfully!", data=out, code=200)

    except Exception as e:
        return _json(False, f"Database error: {str(e)}", data=[], code=500)

# ----------------------------------------------------------
# Add New Assignee (Admin & SuperAdmin only)

# ----------------------------------------------------------
@api_bp.route("/admin/addassignee", methods=["POST"])
def add_assignee():
    if not _require_admin():
        return _json(False, "Access denied. Only Admin or SuperAdmin can add assignees", code=403)

    data = request.get_json(silent=True) or {}
    name     = (data.get("assigneename") or "").strip()
    category = (data.get("productcategory") or "").strip()
    url_norm = _norm_url(data.get("assigneeurl"))

    if not name or not category:
        return _json(False, "Assignee name and product category are required", code=400)

    try:
        dup = db.session.execute(text(f"""
            SELECT id FROM {TBL}
            WHERE LOWER(Assignee_Name) = LOWER(:name)
              AND LOWER(Product_Category) = LOWER(:cat)
            LIMIT 1
        """), {"name": name, "cat": category}).first()

        if dup:
            return _json(False, "Assignee already exists", code=409)

        ins = text(f"""
            INSERT INTO {TBL} (Assignee_Name, Product_Category, Assignee_URL)
            VALUES (:name, :cat, :url)
        """)
        result = db.session.execute(ins, {"name": name, "cat": category, "url": url_norm})
        db.session.commit()
        new_id = getattr(result, "lastrowid", None)

        return _json(True, "New Assignee added successfully!", data={
            "id": new_id, "assigneename": name, "productcategory": category, "assigneeurl": url_norm
        }, code=201)

    except Exception as e:
        db.session.rollback()
        return _json(False, f"Database error: {str(e)}", code=500)

# ----------------------------------------------------------
# Update Assignee (Admin & SuperAdmin only)
# ----------------------------------------------------------
@api_bp.route("/admin/updateassignee", methods=["POST"])
def update_assignee():
    if not _require_admin():
        return _json(False, "Access denied. Only Admin or SuperAdmin can add assignees", code=403)

    data = request.get_json(silent=True) or {}
    try:
        assignee_id = int(data.get("id"))
    except (TypeError, ValueError):
        assignee_id = None

    name     = (data.get("assigneename") or "").strip()
    category = (data.get("productcategory") or "").strip()


    if not assignee_id or not name or not category:
        return _json(False, "Assignee name and product category are required", code=400)

    # URL update logic:
    url_provided = "assigneeurl" in data
    url_norm = _norm_url(data.get("assigneurl") if "assigneurl" in data else data.get("assigneeurl"))

    try:
        exists = db.session.execute(text(f"SELECT id FROM {TBL} WHERE id=:id"), {"id": assignee_id}).first()
        if not exists:
            return _json(False, "Assignee not found", code=404)

        dup = db.session.execute(text(f"""
            SELECT id FROM {TBL}
            WHERE LOWER(Assignee_Name) = LOWER(:name)
              AND LOWER(Product_Category) = LOWER(:cat)
              AND id <> :id
            LIMIT 1
        """), {"name": name, "cat": category, "id": assignee_id}).first()

        if dup:
            return _json(False, "Assignee already exists", code=409)

        if url_provided:
            upd = text(f"""
                UPDATE {TBL}
                SET Assignee_Name = :name,
                    Product_Category = :cat,
                    Assignee_URL = :url
                WHERE id = :id
            """)
            params = {"name": name, "cat": category, "url": url_norm, "id": assignee_id}
        else:
            # keep existing URL as-is
            upd = text(f"""
                UPDATE {TBL}
                SET Assignee_Name = :name,
                    Product_Category = :cat
                WHERE id = :id
            """)
            params = {"name": name, "cat": category, "id": assignee_id}

        db.session.execute(upd, params)
        db.session.commit()

        # If you truly need the leading space before 'Assignee', keep it:
        return _json(True, " Assignee Updated successfully!", data={
            "id": assignee_id, "assigneename": name, "productcategory": category, "assigneeurl": url_norm if url_provided else None
        }, code=201)

    except Exception as e:
        db.session.rollback()
        return _json(False, f"Database error: {str(e)}", code=500)