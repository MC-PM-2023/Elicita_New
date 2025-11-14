from flask import Blueprint, request, jsonify
from db_config import db
from auth.models import ReportData

report_bp = Blueprint('report', __name__, url_prefix='/api/report')

@report_bp.route('/reportdata', methods=['POST'])
def get_report_data():
    data = request.get_json()
    
    if not data or 'column' not in data or 'input' not in data:
        return jsonify({
            "success": False,
            "message": "Column and input are required"
        }), 400

    column_name = data.get('column')
    keyword = data.get('input', '').strip()
    
    valid_columns = ["Project_Code", "Docket", "Project_Title", "Understanding", "Key_Feature", "Overall_Rating"]
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
        column_attr = getattr(ReportData, column_name)
        
        query = db.session.query(ReportData).filter(column_attr.like(f"%{keyword}%"))
        
        count = query.count()
        
        if count == 0:
            return jsonify({
                "success": False,
                "message": "No report data found",
                "data": []
            }), 404

        results = query.all()
        data_list = [item.to_dict() for item in results]

        return jsonify({
            "count": count,
            "success": True,
            "message": "report data retrieved successfully!",
            "data": data_list
        }), 200

    except Exception as e:
        print(f"Error fetching data: {e}")
        db.session.rollback()
        return jsonify({
            "success": False,
            "message": "An internal server error occurred."
        }), 500
