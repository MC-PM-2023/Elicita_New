# models.py
from datetime import datetime
from sqlalchemy import Enum as SAEnum, UniqueConstraint
from db_config import db  # <-- use the ONE shared instance
# class User(db.Model):
#     __tablename__ = "users"
#     __table_args__ = (
#         UniqueConstraint("email", name="uq_users_email"),
#         {"schema": "Elicita_V2"},  # keep if your URI is NOT already pointing to Elicita_V2
#     )
#     id          = db.Column(db.Integer, primary_key=True)
#     first_name  = db.Column(db.String(80))
#     last_name   = db.Column(db.String(80))
#     email       = db.Column(db.String(120), nullable=False)  # unique via constraint above
#     password    = db.Column(db.String(200), nullable=False)  # store a HASH, not plaintext
#     otp         = db.Column(db.String(6))
#     expires_at  = db.Column(db.DateTime)
#     is_verified = db.Column(db.Boolean, nullable=False, server_default=db.text("0"))
#     role        = db.Column(
#         SAEnum("user", "admin", "super admin", name="role_enum"),
#         nullable=False,
#         server_default="user",
#     )
#     created_at  = db.Column(db.DateTime, nullable=False, server_default=db.func.current_timestamp())
#     def __repr__(self) -> str:
#         return f"<User {self.email} | {self.role}>"
class User(db.Model):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("email", name="uq_users_email"),
        {"schema": "Elicita_V2"},
    )


    id          = db.Column(db.Integer, primary_key=True)
    first_name  = db.Column(db.String(80))
    last_name   = db.Column(db.String(80))
    email       = db.Column(db.String(120), nullable=False)
    password    = db.Column(db.String(200), nullable=False)

    # Short-term OTP (10–15 mins validity)
    otp         = db.Column(db.String(6))
    expires_at  = db.Column(db.DateTime)

    # ✅ NEW: Weekly OTP-free window end time
    otp_reverify_until = db.Column(db.DateTime)

    is_verified = db.Column(db.Boolean, nullable=False, server_default=db.text("0"))
    role        = db.Column(
        SAEnum("user", "admin", "super admin", name="role_enum"),
        nullable=False,
        server_default="user",
    )
    created_at  = db.Column(db.DateTime, nullable=False, server_default=db.func.current_timestamp())









class Elicita_User_Profiles(db.Model):
    __tablename__ = 'Elicita_User_Profiles'
    __table_args__ = {'schema': 'Elicita_V2'}

    Id = db.Column(db.Integer, primary_key=True)
    Team = db.Column(db.String(255))
    Name = db.Column(db.String(255))
    Email_ID = db.Column(db.String(255), unique=True, nullable=False)
    Designation = db.Column(db.String(255))
    Image_URL = db.Column(db.String(2048))
    LinkedIn_URL = db.Column(db.String(2048))


# Existing IpcCpcCode Model
class IpcCpcCode(db.Model):
    __tablename__ = 'IPC_CPC_Code'
    __table_args__ = {'schema': 'Elicita_V2'}

    id = db.Column(db.Integer, primary_key=True)
    IPC_CPC = db.Column(db.String(255))
    Definition = db.Column(db.Text)
    Project_Code = db.Column(db.String(255))     
    Product_Category = db.Column(db.String(255)) 
    Type = db.Column(db.String(255))             

    
    def to_dict(self):
        return {
            "id": self.id,
            "ipc_cpc": self.IPC_CPC,
            "definition": self.Definition,
            "project_code": self.Project_Code,     
            "product_category": self.Product_Category, 
            "type": self.Type                      
        }



# Existing ReferenceTable Model (corrected)
class ReferenceTable(db.Model):
    __tablename__ = 'Reference_Table'
    __table_args__ = {'schema': 'Elicita_V2'}
    
    id = db.Column(db.Integer, primary_key=True)
    Project_Code = db.Column(db.String(255))
    Docket = db.Column(db.String(255))
    Project_Title = db.Column(db.String(255))
    Rating_of_Reference = db.Column(db.String(255))
    Observation = db.Column(db.Text)
    Relevant_Excerpts = db.Column(db.Text)
    Reference_No = db.Column(db.String(255))

    def to_dict(self):
        return {
            "id": self.id,
            "projectcode": self.Project_Code,
            "docket": self.Docket,
            "projecttitle": self.Project_Title,
            "rating_of_reference": self.Rating_of_Reference,
            "observation": self.Observation,
            "relevantexcerpts": self.Relevant_Excerpts,
            "reference_no": self.Reference_No

        }

# New StringsTable Model
class StringsTable(db.Model):
    __tablename__ = 'Strings'
    __table_args__ = {'schema': 'Elicita_V2'}

    id = db.Column(db.Integer, primary_key=True)
    Project_Code = db.Column(db.String(255))
    Docket = db.Column(db.String(255))
    Strings = db.Column(db.Text)
    Strings_Hits = db.Column(db.String(255))
    
    def to_dict(self):
        return {
            "id": self.id,
            "projectcode": self.Project_Code,
            "docket": self.Docket,
            "strings": self.Strings,
            "stringshits": self.Strings_Hits
        }
    
class ReportData(db.Model):
    __tablename__ = 'Report_Data'
    __table_args__ = {'schema': 'Elicita_V2'}

    id = db.Column(db.Integer, primary_key=True)
    Project_Code = db.Column(db.String(255))
    Docket = db.Column(db.String(255))
    Project_Title = db.Column(db.String(255))
    Understanding = db.Column(db.Text)
    Key_Feature = db.Column(db.Text)
    Overall_Rating = db.Column(db.String(255))
    
    def to_dict(self):
        return {
            "id": self.id,
            "projectcode": self.Project_Code,
            "docket": self.Docket,
            "projecttitle": self.Project_Title,
            "understanding": self.Understanding,
            "keyfeature": self.Key_Feature,
            "overallrating": self.Overall_Rating
        }


# auth/models.py (Full updated Log class)
from datetime import timedelta # Needed for the fix

class Log(db.Model):
    __tablename__ = 'log'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    email = db.Column(db.String(255))
    date = db.Column(db.Date)                 # '2025-11-07'
    time = db.Column(db.Time)                 # '15:58:40'
    login_time = db.Column(db.DateTime)       # nullable=True
    keyword = db.Column(db.String(255))
    tables_searched = db.Column(db.String(255))
    columns_searched = db.Column(db.String(255))
    fetching_time = db.Column(db.Float)       # seconds
    status = db.Column(db.Text)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "date": self.date.isoformat() if self.date else None,
            "time": self.time.strftime("%H:%M:%S") if self.time else None,
            "login_time": self.login_time.isoformat(sep=" ") if self.login_time else None,
            "keyword": self.keyword,
            "tables_searched": self.tables_searched,
            "columns_searched": self.columns_searched,
            "fetching_time": float(self.fetching_time) if self.fetching_time is not None else None,
            "status": self.status,
        }