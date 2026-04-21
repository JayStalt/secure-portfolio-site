from app import db
from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)


class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(300))
    project_url = db.Column(db.String(300))
    external_link = db.Column(db.String(300))
    category = db.Column(db.String(50), nullable=False)

    # NEW: lower number = higher priority
    display_order = db.Column(db.Integer, default=100, nullable=False)