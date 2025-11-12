from flask import Blueprint, request, jsonify
from db_config import db
from auth.models import IpcCpcCode

from datetime import datetime
import pandas as pd
from flask import Flask, render_template, request, send_file, jsonify,session
from sqlalchemy import create_engine
from sqlalchemy import create_engine
DATABASE_TYPE = 'mysql'
DB_DRIVER = 'pymysql'
USERNAME = 'appsadmin'
PASSWORD = 'appsadmin2025'
HOST = '34.93.75.171'
PORT = '3306'
DATABASE_NAME = 'Elicita_V2'
engine = create_engine(f"{DATABASE_TYPE}+{DB_DRIVER}://{USERNAME}:{PASSWORD}@{HOST}:{PORT}/{DATABASE_NAME}")

ipc_bp = Blueprint('ipc', __name__, url_prefix='/api/ipc')

@ipc_bp.route('/ipcdata', methods=['POST'])
def get_ipc_data():
    username = session.get('user_name', 'Anonymous')
    email=session.get("user_email", "Unknown")
    data = request.get_json()
    
    if not data or 'column' not in data or 'input' not in data:
        return jsonify({
            "success": False,
            "message": "Column and input are required"
        }), 400

    column_name = data.get('column')
    keyword = data.get('input', '').strip()
    
    # Get pagination parameters from the request, with default values
    page = data.get('page', 1)
    per_page = data.get('per_page', 20)

    # Basic input validation for pagination parameters
    if not isinstance(page, int) or page < 1:
        page = 1
    if not isinstance(per_page, int) or per_page < 1:
        per_page = 20

    valid_columns = ['IPC_CPC', 'Definition', 'Project_Code', 'Product_Category', 'Type']
    if column_name not in valid_columns:
        return jsonify({
            "success": False,
            "message": f"Invalid column: {column_name}"
        }), 400

    if not keyword:
        return jsonify({
            "success": False,
            "message": "'column' and 'input' fields are required"
        }), 400

    try:
        ExecutionStartTime = datetime.now()
        column = getattr(IpcCpcCode, column_name)
        filter_clause = column.like(f"%{keyword}%")
        
        # Get the total count of matching records first
        total_count = db.session.query(IpcCpcCode).filter(filter_clause).count()

        # Apply pagination to the query
        offset = (page - 1) * per_page
        results = db.session.query(IpcCpcCode).filter(filter_clause).offset(offset).limit(per_page).all()
        
        if not results:
            return jsonify({
                "success": False,
                "message": "No IPC data found for this page",
                "data": [],
                "scount": total_count  # Renamed total_count to scount
            }), 404

        data_list = [item.to_dict() for item in results]

        return jsonify({
            "success": True,
            "message": "ipc data retrieved successfully!",
            "data": data_list,
            "count": total_count # Renamed total_count to scount
        }), 200

    except Exception as e:
        print(f"Error fetching data: {e}")
        vk = f"Error tracked: {e}"
        db.session.rollback()
        return jsonify({
            "success": False,
            "message": "An internal server error occurred."
        }), 500
    finally:
        # Capture execution details
        ExecutionEndTime = datetime.now()  # Capture the end time as a datetime object
        code_run_time = ExecutionEndTime - ExecutionStartTime  # Calculate runtime
        start_date = ExecutionStartTime.strftime('%Y-%m-%d')
        # Format runtime into a string
        formatted_runtime = str(code_run_time)
        runtimee = str(formatted_runtime).split('.')[0]
        # Format times as readable strings
        start_time = ExecutionStartTime.strftime('%H:%M:%S')
        end_time = ExecutionEndTime.strftime('%H:%M:%S')
        # Log execution details
        log_data = {
            'name':username,
            'tables_searched': 'IPC_CPC Search',
            'email': email,
            'date': start_date,
            'time': start_time,
            'login_time': session.get("login_time", None),
            "keyword":keyword,
            'status': 'Success' if 'vk' not in locals() else vk  # Assuming 'vk' indicates a custom status
        }
        log_df = pd.DataFrame([log_data])  # Convert to DataFrame for SQL insertion
        # Define the SQL table name
        table_name = 'log'
        try:
            # Insert the log data into the MySQL table
            log_df.to_sql(table_name, con=engine, if_exists='append', index=False)
            print("Execution details logged to MySQL successfully.")
        except Exception as e:
            print(f"Error logging execution details to MySQL: {e}")
