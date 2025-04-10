from flask import Blueprint, render_template, redirect, url_for, flash
from app.forms import LoginForm
from app.forms import RegisterForm
from app.models import User
from app import db, bcrypt
from flask_login import login_user, logout_user, login_required
from flask_login import current_user

main = Blueprint('main', __name__)

@main.route('/')
def home():
    return render_template('index.html')

@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Logged in successfully!', 'Success')
            return redirect(url_for('main.home'))
        else:
            flash('Login unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', form=form)

@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.home'))


@main.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))

    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('main.login'))

    return render_template('register.html', form=form)

@main.route('/dashboard')
@login_required
def dashboard():
    if current_user.email != 'admin@example.com' :
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('main.home'))

    return render_template('dashboard.html')
