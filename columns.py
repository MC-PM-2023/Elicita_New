# #columns.py
# from flask import Blueprint, jsonify, request, session, current_app
# from db_config import db
# from sqlalchemy import text, create_engine
# from datetime import datetime
# import pandas as pd
# import pytz  

# # ---------- Dedicated write engine for logs ----------
# DATABASE_TYPE = 'mysql'
# DB_DRIVER = 'pymysql'
# USERNAME = 'appsadmin'
# PASSWORD = 'appsadmin2025'
# HOST = '34.93.75.171'
# PORT = '3306'
# DATABASE_NAME = 'Elicita_V2'
# engine = create_engine(
#     f"{DATABASE_TYPE}+{DB_DRIVER}://{USERNAME}:{PASSWORD}@{HOST}:{PORT}/{DATABASE_NAME}",
#     pool_pre_ping=True
# )

# # ---------- Blueprint ----------
# columns_bp = Blueprint("columns_bp", __name__)

# # ---------- Tables allowed for search / column fetch ----------
# TABLES_TO_FETCH = [
#     'Assignee_Table',
#     'IPC_CPC_Code',
#     'Reference_Table',
#     'Report_Data',
#     'Strings'
# ]

# @columns_bp.route("/api/all-columns", methods=["GET"])
# def get_all_columns():
#     """
#     Fetch and group column names for predefined tables.
#     """
#     grouped_columns_data = {}

#     try:
#         with db.engine.connect() as connection:
#             for table_name in TABLES_TO_FETCH:
#                 query = f"""
#                     SELECT COLUMN_NAME
#                     FROM INFORMATION_SCHEMA.COLUMNS
#                     WHERE TABLE_SCHEMA = '{db.engine.url.database}'
#                       AND TABLE_NAME = '{table_name}'
#                     ORDER BY ORDINAL_POSITION;
#                 """
#                 result = connection.execute(text(query))
#                 column_names = [row[0] for row in result.fetchall()]

#                 table_dict = {}
#                 for col_name in column_names:
#                     table_dict[col_name] = 1 if col_name.lower() == 'id' else ""
#                 grouped_columns_data[table_name] = table_dict

#         return jsonify({
#             "success": True,
#             "message": "Column data retrieved successfully!",
#             "data": [grouped_columns_data]
#         }), 200

#     except Exception as e:
#         return jsonify({
#             "success": False,
#             "message": f"An error occurred while fetching columns: {e}",
#             "data": []
#         }), 500


# @columns_bp.route("/api/search", methods=["GET"])
# def search_data():
#     """
#     Search within an allowed table/column for a query string.
#     Adds execution log with:
#       - name, email, date, time (HH:MM:SS), login_time
#       - tables_searched, columns_searched
#       - keyword
#       - fetching_time (seconds)
#       - status
#     """
#     table_name = request.args.get('table')
#     column_name = request.args.get('column')
#     search_query = request.args.get('query')
    
#     # --- UPDATE: Get match_type, default to 'partial' ---
#     match_type = request.args.get('match_type', 'partial')

#     # ---------- Validate inputs ----------
#     if not all([table_name, column_name, search_query]):
#         return jsonify({"success": False, "message": "Missing required parameters: table, column, query."}), 400
#     if table_name not in TABLES_TO_FETCH:
#         return jsonify({"success": False, "message": "Invalid table name."}), 400

   
#     IST = pytz.timezone('Asia/Kolkata')
#     execution_start = datetime.now(IST) 

#     # Prepare for logging
#     error_msg = None
#     results = []
#     is_ipc_cpc_table = (table_name == 'IPC_CPC_Code')

#     try:
#         with db.engine.connect() as connection:
#             # Ensure column exists
#             column_check_query = text(f"""
#                 SELECT COUNT(*)
#                 FROM INFORMATION_SCHEMA.COLUMNS
#                 WHERE TABLE_SCHEMA = '{db.engine.url.database}'
#                   AND TABLE_NAME   = :t
#                   AND COLUMN_NAME  = :c;
#             """)
#             if connection.execute(column_check_query, {"t": table_name, "c": column_name}).scalar() == 0:
#                 return jsonify({"success": False, "message": f"Column '{column_name}' does not exist in table '{table_name}'."}), 400

#             # --- UPDATE: Set operator and qval based on match_type ---
#             if match_type == 'exact':
#                 operator = "="
#                 qval = search_query
#             else:  # Default to partial match
#                 operator = "LIKE"
#                 qval = f"%{search_query}%"

#             # --- UPDATE: Use dynamic operator in the query ---
#             search_sql = text(f"""
#                 SELECT *
#                 FROM `{table_name}`
#                 WHERE `{column_name}` {operator} :q
#             """)
            
#             result = connection.execute(search_sql, {"q": qval})

#             # Safer way to get columns
#             column_headers = list(result.keys())
#             raw_rows = [dict(zip(column_headers, row)) for row in result.fetchall()]

#         # ---------- Special grouping for IPC_CPC_Code ----------
#         if is_ipc_cpc_table:
#             grouped = {}
#             for row in raw_rows:
#                 key = row.get('IPC_CPC')
#                 if not key:
#                     # Keep rows without a key as-is
#                     results.append(row)
#                     continue

#                 if key not in grouped:
#                     grouped[key] = {
#                         "Definition": set(),
#                         "IPC_CPC": key,
#                         "Product_Category": set(),
#                         "Project_Code": set(),
#                         "Type": row.get('Type'),
#                         "id": row.get('id')
#                     }

#                 if row.get('Definition'):
#                     grouped[key]["Definition"].add(row['Definition'])
#                 if row.get('Product_Category'):
#                     grouped[key]["Product_Category"].add(row['Product_Category'])
#                 if row.get('Project_Code'):
#                     grouped[key]["Project_Code"].add(row['Project_Code'])
#                 if grouped[key]["Type"] != "Project" and row.get('Type') == "Project":
#                     grouped[key]["Type"] = "Project"

#             # Build final rows from grouped
#             for _, data in grouped.items():
#                 # sort project codes by trailing number, desc; top 10
#                 pcodes = [p for p in data['Project_Code'] if p]
#                 sortable = []
#                 for code in pcodes:
#                     try:
#                         n = int(code.split('-')[-1])
#                     except Exception:
#                         n = -1
#                     sortable.append((n, code))
#                 sortable.sort(key=lambda x: x[0], reverse=True)
#                 top10 = [c for _, c in sortable[:10]]

#                 categories = sorted([p for p in data['Product_Category'] if p])

#                 results.append({
#                     "Definition": " | ".join(sorted(data["Definition"])) if data["Definition"] else None,
#                     "IPC_CPC": data["IPC_CPC"],
#                     "Product_Category": " | ".join(categories) if categories else None,
#                     "Project_Code": " | ".join(top10) if top10 else None,
#                     "Type": data["Type"],
#                     "id": data["id"]
#                 })
#         else:
#             results = raw_rows

#         # Success response
#         return jsonify({
#             "success": True,
#             "message": f"Search results for '{search_query}' in '{table_name}.{column_name}'",
#             "table_name": table_name,
#             "column_name": column_name,
#             "result_count": len(results),
#             "results": results
#         }), 200

#     except Exception as e:
#         error_msg = f"Error: {e}"
#         current_app.logger.exception("Search failed")
#         return jsonify({
#             "success": False,
#             "message": f"An error occurred during search: {e}",
#             "results": []
#         }), 500

#     finally:
#         # ---------- Build the log row ----------
        
 
#         execution_end = datetime.now(IST) 
        
#         fetching_seconds = round((execution_end - execution_start).total_seconds(), 2)  # seconds with 2 decimals

#         # Session-backed identity
#         username = session.get('user_name', 'Anonymous')
#         email = session.get('user_email', 'Unknown')
#         login_time = session.get("login_time")  # already string (from login route)

#         log_row = {
#             "name": username,
#             "email": email,
#             "date": execution_start.strftime('%Y-%m-%d'),   
#             "time": execution_start.strftime('%H:%M:%S'),   
#             "login_time": login_time,
#             "keyword": search_query,
#             "tables_searched": table_name,
#             "columns_searched": column_name,                # <-- NEW
#             "fetching_time": fetching_seconds,               # <-- NEW (seconds)
#             "status": "Success" if error_msg is None else error_msg
#         }

#         try:
#             pd.DataFrame([log_row]).to_sql(
#                 "log",
#                 con=engine,
#                 if_exists='append',
#                 index=False
#             )
#         except Exception as e:
#             # Don't break the request because of a logging failure
#             current_app.logger.warning(f"Failed to write log row: {e}")







# columns.py
# columns.py
from flask import Blueprint, jsonify, request, session, current_app
from sqlalchemy import text
from datetime import datetime
import pytz

from db_config import db
from logger import write_log_row

columns_bp = Blueprint("columns_bp", __name__)

TABLES_TO_FETCH = [
    'Assignee_Table',
    'IPC_CPC_Code',
    'Reference_Table',
    'Report_Data',
    'Strings'
]

@columns_bp.route("/api/all-columns", methods=["GET"])
def get_all_columns():
    grouped_columns_data = {}
    try:
        with db.engine.connect() as connection:
            for table_name in TABLES_TO_FETCH:
                query = f"""
                    SELECT COLUMN_NAME
                    FROM INFORMATION_SCHEMA.COLUMNS
                    WHERE TABLE_SCHEMA = '{db.engine.url.database}'
                      AND TABLE_NAME = '{table_name}'
                    ORDER BY ORDINAL_POSITION;
                """
                result = connection.execute(text(query))
                column_names = [row[0] for row in result.fetchall()]

                table_dict = {}
                for col_name in column_names:
                    table_dict[col_name] = 1 if col_name.lower() == 'id' else ""
                grouped_columns_data[table_name] = table_dict

        return jsonify({"success": True, "message": "Column data retrieved successfully!", "data": [grouped_columns_data]}), 200

    except Exception as e:
        return jsonify({"success": False, "message": f"An error occurred while fetching columns: {e}", "data": []}), 500


@columns_bp.route("/api/search", methods=["GET"])
def search_data():
    table_name = request.args.get('table')
    column_name = request.args.get('column')
    search_query = request.args.get('query')
    match_type = request.args.get('match_type', 'partial')  # 'partial' | 'exact'

    if not all([table_name, column_name, search_query]):
        return jsonify({"success": False, "message": "Missing required parameters: table, column, query."}), 400
    if table_name not in TABLES_TO_FETCH:
        return jsonify({"success": False, "message": "Invalid table name."}), 400

    IST = pytz.timezone('Asia/Kolkata')
    execution_start = datetime.now(IST)

    error_msg = None
    results = []
    is_ipc_cpc_table = (table_name == 'IPC_CPC_Code')

    try:
        with db.engine.connect() as connection:
            # Ensure column exists
            column_check_query = text(f"""
                SELECT COUNT(*)
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = '{db.engine.url.database}'
                  AND TABLE_NAME   = :t
                  AND COLUMN_NAME  = :c;
            """)
            if connection.execute(column_check_query, {"t": table_name, "c": column_name}).scalar() == 0:
                return jsonify({"success": False, "message": f"Column '{column_name}' does not exist in table '{table_name}'."}), 400

            # Dynamic operator
            if match_type == 'exact':
                operator = "="
                qval = search_query
            else:
                operator = "LIKE"
                qval = f"%{search_query}%"

            search_sql = text(f"""
                SELECT *
                FROM `{table_name}`
                WHERE `{column_name}` {operator} :q
            """)
            result = connection.execute(search_sql, {"q": qval})

            column_headers = list(result.keys())
            raw_rows = [dict(zip(column_headers, row)) for row in result.fetchall()]

        # Grouping for IPC_CPC_Code
        if is_ipc_cpc_table:
            grouped = {}
            for row in raw_rows:
                key = row.get('IPC_CPC')
                if not key:
                    results.append(row)
                    continue
                if key not in grouped:
                    grouped[key] = {
                        "Definition": set(),
                        "IPC_CPC": key,
                        "Product_Category": set(),
                        "Project_Code": set(),
                        "Type": row.get('Type'),
                        "id": row.get('id')
                    }
                if row.get('Definition'):
                    grouped[key]["Definition"].add(row['Definition'])
                if row.get('Product_Category'):
                    grouped[key]["Product_Category"].add(row['Product_Category'])
                if row.get('Project_Code'):
                    grouped[key]["Project_Code"].add(row['Project_Code'])
                if grouped[key]["Type"] != "Project" and row.get('Type') == "Project":
                    grouped[key]["Type"] = "Project"

            for _, data in grouped.items():
                pcodes = [p for p in data['Project_Code'] if p]
                sortable = []
                for code in pcodes:
                    try:
                        n = int(code.split('-')[-1])
                    except Exception:
                        n = -1
                    sortable.append((n, code))
                sortable.sort(key=lambda x: x[0], reverse=True)
                top10 = [c for _, c in sortable[:10]]

                categories = sorted([p for p in data['Product_Category'] if p])

                results.append({
                    "Definition": " | ".join(sorted(data["Definition"])) if data["Definition"] else None,
                    "IPC_CPC": data["IPC_CPC"],
                    "Product_Category": " | ".join(categories) if categories else None,
                    "Project_Code": " | ".join(top10) if top10 else None,
                    "Type": data["Type"],
                    "id": data["id"]
                })
        else:
            results = raw_rows

        return jsonify({
            "success": True,
            "message": f"Search results for '{search_query}' in '{table_name}.{column_name}'",
            "table_name": table_name,
            "column_name": column_name,
            "result_count": len(results),
            "results": results
        }), 200

    except Exception as e:
        error_msg = f"Error: {e}"
        current_app.logger.exception("Search failed")
        return jsonify({"success": False, "message": f"An error occurred during search: {e}", "results": []}), 500

    finally:
        # ✅ only log if user is logged in
        if session.get("user_id"):
            execution_end = datetime.now(IST)
            fetching_seconds = round((execution_end - execution_start).total_seconds(), 2)

            try:
                write_log_row(
                    name=session.get('user_name', 'Anonymous'),
                    email=session.get('user_email', 'Unknown'),
                    date_str=execution_start.strftime('%Y-%m-%d'),  # IST
                    time_str=execution_start.strftime('%H:%M:%S'),  # IST
                    login_time_str=session.get("login_time"),       # converted to IST inside helper
                    keyword=search_query,
                    tables_searched=table_name,
                    columns_searched=column_name,
                    fetching_time=fetching_seconds,
                    status="Success" if error_msg is None else error_msg
                )
            except Exception as _e:
                current_app.logger.warning(f"Failed to write log row: {_e}")
        else:
            pass


