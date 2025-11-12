# #columns.py
# from flask import Blueprint, jsonify, request, session
# from db_config import db
# from sqlalchemy import text, create_engine
# from datetime import datetime
# import pandas as pd

# # Database Configuration (Assuming these variables are available in db_config.py or globally)
# DATABASE_TYPE = 'mysql'
# DB_DRIVER = 'pymysql'
# USERNAME = 'appsadmin'
# PASSWORD = 'appsadmin2025'
# HOST = '34.93.75.171'
# PORT = '3306'
# DATABASE_NAME = 'Elicita_V2'
# engine = create_engine(f"{DATABASE_TYPE}+{DB_DRIVER}://{USERNAME}:{PASSWORD}@{HOST}:{PORT}/{DATABASE_NAME}")

# # Create a new Blueprint for the columns API
# columns_bp = Blueprint("columns_bp", __name__)

# # Define the list of tables to fetch columns for
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
#     Fetches and groups all column names for a predefined list of tables.
#     Returns the data in a nested JSON format.
#     """
#     grouped_columns_data = {}

#     try:
#         # Note: Assumes db.engine is properly set up in db_config
#         with db.engine.connect() as connection:
#             # Loop through each table to retrieve its column names
#             for table_name in TABLES_TO_FETCH:
#                 query = f"""
#                 SELECT COLUMN_NAME
#                 FROM INFORMATION_SCHEMA.COLUMNS
#                 WHERE TABLE_SCHEMA = '{db.engine.url.database}' AND TABLE_NAME = '{table_name}'
#                 ORDER BY ORDINAL_POSITION;
#                 """
                
#                 result = connection.execute(text(query))
#                 column_names = [row[0] for row in result.fetchall()]
                
#                 table_dict = {}
#                 for col_name in column_names:
#                     # Check for 'id' using lower() for safety and assign 1
#                     if col_name.lower() == 'id':
#                         table_dict[col_name] = 1 
#                     else:
#                         table_dict[col_name] = ""
                
#                 grouped_columns_data[table_name] = table_dict
        
#         response = {
#             "success": True,
#             "message": "Column data retrieved successfully!",
#             "data": [grouped_columns_data]
#         }
#         return jsonify(response), 200

#     except Exception as e:
#         response = {
#             "success": False,
#             "message": f"An error occurred while fetching columns: {e}",
#             "data": []
#         }
#         return jsonify(response), 500

# @columns_bp.route("/api/search", methods=["GET"])
# def search_data():
#     """
#     Performs a search based on a table name, column name, and search query.
#     Expected URL parameters:
#     - table: The name of the table to search (e.g., 'Assignee_Table').
#     - column: The name of the column to search (e.g., 'Status').
#     - query: The search query string (e.g., 'In Progress').
#     """
#     table_name = request.args.get('table')
#     column_name = request.args.get('column')
#     search_query = request.args.get('query')

#     # Basic input validation
#     if not all([table_name, column_name, search_query]):
#         return jsonify({"success": False, "message": "Missing required parameters: table, column, and query."}), 400

#     # Sanitize inputs to prevent SQL injection
#     if table_name not in TABLES_TO_FETCH:
#         return jsonify({"success": False, "message": "Invalid table name."}), 400

#     results = []
    
#     # Check if the special grouping logic is needed
#     is_ipc_cpc_table = (table_name == 'IPC_CPC_Code')
    
#     try:
#         username = session.get('user_name', 'Anonymous')
#         email=session.get("user_email", "Unknown")
#         ExecutionStartTime = datetime.now()
#         vk = "" # Initialize vk for logging in case of success
        
#         # NOTE: Using the SQLAlchemy engine created globally (or from db_config)
#         with db.engine.connect() as connection:
#             # Check if the column exists in the specified table
#             column_check_query = text(f"""
#                 SELECT COUNT(*)
#                 FROM INFORMATION_SCHEMA.COLUMNS
#                 WHERE TABLE_SCHEMA = '{db.engine.url.database}' AND TABLE_NAME = '{table_name}' AND COLUMN_NAME = '{column_name}';
#             """)
#             if connection.execute(column_check_query).scalar() == 0:
#                 return jsonify({"success": False, "message": f"Column '{column_name}' does not exist in table '{table_name}'."}), 400

#             # Dynamic SQL query using parameterized query for security
#             search_query_sql = f"""
#                 SELECT * FROM `{table_name}`
#                 WHERE `{column_name}` LIKE :search_query_param
#             """

#             search_param_value = f"%{search_query}%"
            
#             result = connection.execute(text(search_query_sql), {'search_query_param': search_param_value})
            
#             column_headers = [col[0] for col in result.cursor.description]
            
#             # Fetch all rows
#             raw_results = []
#             for row in result.fetchall():
#                 row_dict = dict(zip(column_headers, row))
#                 raw_results.append(row_dict)

#         # 🚀 START: Special Grouping Logic for IPC_CPC_Code table 🚀
#         if is_ipc_cpc_table:
#             grouped_data = {}
#             for row in raw_results:
#                 # Use the exact IPC_CPC value as the grouping key
#                 ipc_cpc_key = row.get('IPC_CPC')
                
#                 if ipc_cpc_key:
#                     # 1. Initialize the group entry if it doesn't exist
#                     if ipc_cpc_key not in grouped_data:
#                         grouped_data[ipc_cpc_key] = {
#                             "Definition": set(), 
#                             "IPC_CPC": ipc_cpc_key, 
#                             "Product_Category": set(), 
#                             "Project_Code": set(), 
#                             "Type": row.get('Type'), # Initialize Type with the current row's value
#                             "id": row.get('id')
#                         }
                    
#                     # 2. Aggregate values using sets to ensure unique entries
#                     if row.get('Definition'):
#                         grouped_data[ipc_cpc_key]["Definition"].add(row['Definition'])
                    
#                     if row.get('Product_Category'):
#                         grouped_data[ipc_cpc_key]["Product_Category"].add(row['Product_Category'])
                        
#                     if row.get('Project_Code'):
#                         grouped_data[ipc_cpc_key]["Project_Code"].add(row['Project_Code'])

#                     # 3. Check and PRIORITY SET 'Type' to "Project" if found
#                     if grouped_data[ipc_cpc_key]["Type"] != "Project" and row.get('Type') == "Project":
#                          grouped_data[ipc_cpc_key]["Type"] = "Project"

#             # Convert sets to '|' separated strings and reconstruct the final results list
#             for key, data in grouped_data.items():
                
#                 # --- Project_Code Sorting (Descending by hyphen number, Top 10) ---
#                 project_codes_raw = [p for p in data['Project_Code'] if p]
                
#                 # Create a list of tuples (numeric_part, original_code)
#                 sortable_codes = []
#                 for code in project_codes_raw:
#                     try:
#                         # Extract number after the last hyphen
#                         numeric_part = int(code.split('-')[-1])
#                         sortable_codes.append((numeric_part, code))
#                     except (ValueError, IndexError):
#                         # Handle codes without a hyphen number or invalid format by giving them a low sort priority (0)
#                         sortable_codes.append((0, code))
                
#                 # Sort in descending order by the numeric part
#                 sortable_codes.sort(key=lambda x: x[0], reverse=True)

#                 # Extract original codes, take top 10, and join with ' | '
#                 top_10_codes = [code_tuple[1] for code_tuple in sortable_codes[:10]]
#                 project_code_output = " | ".join(top_10_codes) if top_10_codes else None
#                 # --- End Project_Code Sorting ---


#                 # Sort Product Categories (standard alphabetical sort)
#                 product_categories = sorted([p for p in data['Product_Category'] if p])
                
#                 results.append({
#                     "Definition": " | ".join(data["Definition"]),
#                     "IPC_CPC": data["IPC_CPC"],
#                     "Product_Category": " | ".join(product_categories) if product_categories else None,
#                     "Project_Code": project_code_output,
#                     "Type": data["Type"],
#                     "id": data["id"]
#                 })
#         else:
#             # For all other tables, return the raw results list as is
#             results = raw_results

#         # ----------------------------------------------------
#         # Get the count of the final results list
#         # ----------------------------------------------------
#         result_count = len(results) 

#         # Construct the success response
#         response = {
#             "success": True,
#             "message": f"Search results for '{search_query}' in '{table_name}.{column_name}'",
#             "table_name": table_name,
#             "column_name": column_name,
#             "result_count": result_count,  # Include the count here
#             "results": results
#         }
#         return jsonify(response), 200
        
#     except Exception as e:
#         vk = f"Error tracked: {e}"
#         response = {
#             "success": False,
#             "message": f"An error occurred during search: {e}",
#             "results": []
#         }
#         return jsonify(response), 500
#     finally:
#         # Capture execution details
#         ExecutionEndTime = datetime.now() 
#         start_date = ExecutionStartTime.strftime('%Y-%m-%d')
#         start_time = ExecutionStartTime.strftime('%H:%M:%S')
        
#         # Log execution details
#         log_data = {
#             'name':username,
#             'tables_searched': table_name,
#             'email': email,
#             'date': start_date,
#             'time': start_time,
#             'login_time': session.get("login_time", None),
#             "keyword":search_query,
#             'status': 'Success' if not vk or vk.startswith("Error") else vk
#         }
#         log_df = pd.DataFrame([log_data]) 
#         # Define the SQL table name
#         table_name_log = 'log'
#         try:
#             # Insert the log data into the MySQL table
#             log_df.to_sql(table_name_log, con=engine, if_exists='append', index=False)
#             print("Execution details logged to MySQL successfully.")
#         except Exception as e:
#             print(f"Error logging execution details to MySQL: {e}")






# #change
# from flask import Blueprint, jsonify, request, session, current_app
# from db_config import db
# from sqlalchemy import text, create_engine
# from datetime import datetime
# import pandas as pd

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

#     # ---------- Validate inputs ----------
#     if not all([table_name, column_name, search_query]):
#         return jsonify({"success": False, "message": "Missing required parameters: table, column, query."}), 400
#     if table_name not in TABLES_TO_FETCH:
#         return jsonify({"success": False, "message": "Invalid table name."}), 400

#     # Capture start time for logging + fetching_time
#     execution_start = datetime.now()

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

#             # Parameterized LIKE search
#             search_sql = text(f"""
#                 SELECT *
#                 FROM `{table_name}`
#                 WHERE `{column_name}` LIKE :q
#             """)
#             qval = f"%{search_query}%"
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
#         execution_end = datetime.now()
#         fetching_seconds = round((execution_end - execution_start).total_seconds(), 2)  # seconds with 2 decimals

#         # Session-backed identity
#         username = session.get('user_name', 'Anonymous')
#         email = session.get('user_email', 'Unknown')
#         login_time = session.get("login_time")  # already string (from login route)

#         log_row = {
#             "name": username,
#             "email": email,
#             "date": execution_start.strftime('%Y-%m-%d'),
#             "time": execution_start.strftime('%H:%M:%S'),   # <-- "16:45:22"
#             "login_time": login_time,
#             "keyword": search_query,
#             "tables_searched": table_name,
#             "columns_searched": column_name,                 # <-- NEW
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





# from flask import Blueprint, jsonify, request, session, current_app
# from db_config import db
# from sqlalchemy import text, create_engine
# from datetime import datetime
# import pandas as pd

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

#     # Capture start time for logging + fetching_time
#     execution_start = datetime.now()

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
#         execution_end = datetime.now()
#         fetching_seconds = round((execution_end - execution_start).total_seconds(), 2)  # seconds with 2 decimals

#         # Session-backed identity
#         username = session.get('user_name', 'Anonymous')
#         email = session.get('user_email', 'Unknown')
#         login_time = session.get("login_time")  # already string (from login route)

#         log_row = {
#             "name": username,
#             "email": email,
#             "date": execution_start.strftime('%Y-%m-%d'),
#             "time": execution_start.strftime('%H:%M:%S'),   # <-- "16:45:22"
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


            


#final
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
from flask import Blueprint, jsonify, request, session, current_app
from db_config import db
from sqlalchemy import text, create_engine
from sqlalchemy.dialects.mysql import VARCHAR, FLOAT
from datetime import datetime
import pandas as pd
import pytz
import os

# ---------- Optional JWT fallback for identity ----------
try:
    import jwt  # PyJWT
except Exception:
    jwt = None

AUTH_SECRET = os.getenv("AUTH_JWT_SECRET", "very-strong-secret-change-me")
AUTH_ALGO   = "HS256"

def identity_from_jwt(auth_header: str):
    """Return (name, email) from Bearer JWT or (None, None)."""
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return (None, None)
    token = auth_header.split(" ", 1)[1].strip()
    if not token or jwt is None:
        return (None, None)
    try:
        payload = jwt.decode(token, AUTH_SECRET, algorithms=[AUTH_ALGO])
        email = payload.get("email")
        name = payload.get("firstname") or payload.get("first_name") or payload.get("name")
        if not name and email:
            name = email.split("@")[0]
        return (name, email)
    except Exception:
        return (None, None)

# ---------- Dedicated write engine for logs ----------
DATABASE_TYPE = 'mysql'
DB_DRIVER = 'pymysql'
USERNAME = 'appsadmin'
PASSWORD = 'appsadmin2025'
HOST = '34.93.75.171'
PORT = '3306'
DATABASE_NAME = 'Elicita_V2'

engine = create_engine(
    f"{DATABASE_TYPE}+{DB_DRIVER}://{USERNAME}:{PASSWORD}@{HOST}:{PORT}/{DATABASE_NAME}",
    pool_pre_ping=True
)

# ---------- Blueprint ----------
columns_bp = Blueprint("columns_bp", __name__)

# ---------- Tables allowed ----------
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
                table_dict = {col: (1 if col.lower() == 'id' else "") for col in column_names}
                grouped_columns_data[table_name] = table_dict

        return jsonify({
            "success": True,
            "message": "Column data retrieved successfully!",
            "data": [grouped_columns_data]
        }), 200

    except Exception as e:
        current_app.logger.exception("get_all_columns failed")
        return jsonify({
            "success": False,
            "message": f"An error occurred while fetching columns: {e}",
            "data": []
        }), 500


@columns_bp.route("/api/search", methods=["GET"])
def search_data():
    """
    Search within an allowed table/column for a query string.
    Logs:
      - name, email, date, time (IST), login_time (DATETIME or NULL)
      - tables_searched, columns_searched, keyword, fetching_time (sec), status
    Supports: match_type=partial (default) or exact
    """
    table_name   = request.args.get('table')
    column_name  = request.args.get('column')
    search_query = request.args.get('query')
    match_type   = (request.args.get('match_type') or 'partial').strip().lower()

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
            # column exists?
            column_check_query = text(f"""
                SELECT COUNT(*)
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = '{db.engine.url.database}'
                  AND TABLE_NAME   = :t
                  AND COLUMN_NAME  = :c;
            """)
            if connection.execute(column_check_query, {"t": table_name, "c": column_name}).scalar() == 0:
                return jsonify({"success": False, "message": f"Column '{column_name}' does not exist in table '{table_name}'."}), 400

            # operator
            if match_type == 'exact':
                operator, qval = "=", search_query
            else:
                operator, qval = "LIKE", f"%{search_query}%"

            search_sql = text(f"""
                SELECT *
                FROM `{table_name}`
                WHERE `{column_name}` {operator} :q
            """)
            result = connection.execute(search_sql, {"q": qval})

            cols = list(result.keys())
            raw_rows = [dict(zip(cols, row)) for row in result.fetchall()]

        if is_ipc_cpc_table:
            grouped = {}
            for row in raw_rows:
                key = row.get('IPC_CPC')
                if not key:
                    results.append(row); continue
                if key not in grouped:
                    grouped[key] = {
                        "Definition": set(),
                        "IPC_CPC": key,
                        "Product_Category": set(),
                        "Project_Code": set(),
                        "Type": row.get('Type'),
                        "id": row.get('id')
                    }
                if row.get('Definition'):       grouped[key]["Definition"].add(row['Definition'])
                if row.get('Product_Category'): grouped[key]["Product_Category"].add(row['Product_Category'])
                if row.get('Project_Code'):     grouped[key]["Project_Code"].add(row['Project_Code'])
                if grouped[key]["Type"] != "Project" and row.get('Type') == "Project":
                    grouped[key]["Type"] = "Project"

            for _, data in grouped.items():
                pcodes = [p for p in data['Project_Code'] if p]
                sortable = []
                for code in pcodes:
                    try:    n = int(str(code).split('-')[-1])
                    except: n = -1
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
        return jsonify({
            "success": False,
            "message": f"An error occurred during search: {e}",
            "results": []
        }), 500

    finally:
        # --------- LOG WRITE (insert NULL for missing login_time) ---------
        try:
            execution_end = datetime.now(IST)
            fetching_seconds = round((execution_end - execution_start).total_seconds(), 2)

            # identity via session, then JWT
            username   = (session.get('user_name') or '').strip()
            email      = (session.get('user_email') or '').strip()
            login_time_raw = (session.get("login_time") or '').strip()

            if not (username and email):
                jname, jemail = identity_from_jwt(request.headers.get("Authorization"))
                if jname:  username = username or jname
                if jemail: email    = email or jemail

            # normalize login_time -> DATETIME or None
            login_time_val = None
            if login_time_raw:
                # try parse 'YYYY-MM-DD HH:MM:SS%z' (UTC) → naive 'YYYY-MM-DD HH:MM:SS'
                try:
                    if '+' in login_time_raw or login_time_raw.endswith('Z'):
                        try:
                            dt = datetime.strptime(login_time_raw.replace('Z','+0000'), '%Y-%m-%d %H:%M:%S%z')
                        except ValueError:
                            # fallback: try ISO-ish
                            dt = datetime.fromisoformat(login_time_raw)
                        dt = dt.astimezone(pytz.UTC).replace(tzinfo=None)
                        login_time_val = dt.strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        # already a plain 'YYYY-MM-DD HH:MM:SS' string
                        login_time_val = login_time_raw
                except Exception:
                    # if parse fails, still try to store as text if column is VARCHAR,
                    # but safest for DATETIME is None to avoid invalid value
                    login_time_val = None

            # final identity fallbacks
            username = username or 'Anonymous'
            email    = email or 'Unknown'

            log_row = {
                "name": username,
                "email": email,
                "date": execution_start.strftime('%Y-%m-%d'),
                "time": execution_start.strftime('%H:%M:%S'),
                "login_time": login_time_val,          # None -> inserts NULL (valid for DATETIME)
                "keyword": search_query or "",
                "tables_searched": table_name or "",
                "columns_searched": column_name or "",
                "fetching_time": fetching_seconds,
                "status": "Success" if error_msg is None else str(error_msg)[:255]
            }

            df = pd.DataFrame([log_row])

            # Replace NaN/NaT with None so MySQL gets NULLs (esp. login_time)
            df = df.where(pd.notnull(df), None)

            df.to_sql(
                "log",
                con=engine,
                if_exists='append',
                index=False,
                method='multi',
                dtype={
                    "name":            VARCHAR(100),
                    "email":           VARCHAR(150),
                    "date":            VARCHAR(10),
                    "time":            VARCHAR(8),
                    # NOTE: no dtype for login_time -> use table's DATETIME column
                    "keyword":         VARCHAR(255),
                    "tables_searched": VARCHAR(64),
                    "columns_searched":VARCHAR(64),
                    "fetching_time":   FLOAT(asdecimal=False),
                    "status":          VARCHAR(255),
                }
            )
        except Exception as le:
            current_app.logger.warning(f"Failed to write log row: {le}")
