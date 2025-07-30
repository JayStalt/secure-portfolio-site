import os
from dotenv import load_dotenv

load_dotenv()

# This is the path Render will mount the persistent disk to
persistent_dir = '/var/data'

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'fallback-secret-key')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', f'sqlite:///{os.path.join(persistent_dir, "site.db")}')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DEBUG = True