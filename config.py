import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key'

    if os.environ.get("RENDER"):
        # Render environment → use temporary SQLite (safe fallback)
        SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    else:
        # Local environment → use instance folder
        SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'instance', 'site.db')

    SQLALCHEMY_TRACK_MODIFICATIONS = False