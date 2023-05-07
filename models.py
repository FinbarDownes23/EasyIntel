from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    vt_api_key = db.Column(db.String(120), nullable=True)
    ibm_api_key = db.Column(db.String(120), nullable=True)
    ipapi_api_key = db.Column(db.String(120), nullable=True)
    abuseipdb_api_key = db.Column(db.String(120), nullable=True)
