from app import db, login_manager
from flask_login import UserMixin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)


def __repr__(self):
    return f"User('{self.username}', '{self.email}')"


class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(255))
    project_url = db.Column(db.String(300), nullable=True)
    external_link = db.Column(db.String(255))
    category = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return f"Project('{self.title}')"
