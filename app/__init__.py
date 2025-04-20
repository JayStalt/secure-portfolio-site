from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from config import Config
import traceback
from flask import jsonify

db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
login_manager.login_view = 'main.login'  # redirect if not logged in
login_manager.login_message_category = 'info'

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    login_manager.init_app(app)

    from app.routes import main
    app.register_blueprint(main)

    import traceback
    from flask import jsonify

    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(traceback.format_exc())
        return jsonify({"error": "Internal Server Error"}), 500

    return app