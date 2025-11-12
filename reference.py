from flask import Blueprint, request, jsonify
from db_config import db
from auth.models import ReferenceTable

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
reference_bp = Blueprint('reference', __name__, url_prefix='/api/reference')

reference_bp = Blueprint('reference', __name__, url_prefix='/api/reference')

@reference_bp.route('/referencedata', methods=['POST'])
def get_reference_data():
    username = session.get('user_name', 'Anonymous')
    email=session.get("user_email", "Unknown")
    data = request.get_json()
    
    # Validation
    if not data or 'column' not in data or 'input' not in data:
        return jsonify({
            "success": False,
            "message": "Column and input are required"
        }), 400

    column_name = data.get('column')
    keyword = data.get('input', '').strip()
    
    valid_columns = ["Project_Code", "Docket", "Project_Title", "Rating_of_Reference", "Observation", "Relevant_Excerpts","Reference_No"]
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
        # Get the attribute for the specified column
        column_attr = getattr(ReferenceTable, column_name)
        
        # Build the query
        query = db.session.query(ReferenceTable).filter(column_attr.like(f"%{keyword}%"))
        
        # Get the count
        count = query.count()
        
        if count == 0:
            return jsonify({
                "success": False,
                "message": "No reference data found",
                "data": []
            }), 404

        # Fetch results and format them
        results = query.all()
        data_list = [item.to_dict() for item in results]

        return jsonify({
            "count": count,
            "success": True,
            "message": "reference data retrieved successfully!",
            "data": data_list
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
            'tables_searched': 'Reference Search',
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

