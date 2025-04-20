from flask import Blueprint, render_template, redirect, url_for, flash
from app.forms import LoginForm
from app.forms import RegisterForm
from app.forms import ProjectForm
from app.models import Project
from app.models import User
from app import db, bcrypt
from flask_login import login_user, logout_user, login_required
from flask_login import current_user
from app.logger import log_event
import os
from collections import Counter
from datetime import datetime
import requests
from flask import request
import base64
import json
import jwt  # PyJWT
from flask import current_app

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
            log_event(f"Successful login: {user.email}")  # ✅ Logging success
            flash('Logged in successfully!', 'success')
            return redirect(url_for('main.home'))
        else:
            log_event(f"Failed login attempt for email: {form.email.data}")  # Logging failure
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
        log_event(f"New user registered: {form.email.data}")
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


@main.route('/admin/projects/new', methods=['GET', 'POST'])
@login_required
def add_project():
    form = ProjectForm()
    if form.validate_on_submit():
        new_project = Project(
            title=form.title.data,
            description=form.description.data,
            image_url=form.image_url.data,
            external_link=form.project_url.data,
            category=form.category.data  # <-- NEW!
        )
        db.session.add(new_project)
        db.session.commit()
        flash('Project added successfully!', 'success')
        return redirect(url_for('main.admin_projects'))

    return render_template('admin_add_project.html', form=form)


@main.route('/projects')
def projects():
    cyber = Project.query.filter_by(category='cyber').all()
    fullstack = Project.query.filter_by(category='fullstack').all()
    games = Project.query.filter_by(category='games').all()
    writing = Project.query.filter_by(category='writing').all()
    return render_template('projects_tabs.html', cyber=cyber, fullstack=fullstack, games=games, writing=writing)


@main.route('/admin/projects')
@login_required
def admin_projects():
    if current_user.email != 'admin@example.com':
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('main.home'))

    projects = Project.query.all()
    return render_template('admin_projects.html', projects=projects)


@main.route('/admin/projects/edit/<int:project_id>', methods=['GET', 'POST'])
@login_required
def edit_project(project_id):
    project = Project.query.get_or_404(project_id)
    form = ProjectForm()

    if form.validate_on_submit():
        project.title = form.title.data
        project.description = form.description.data
        project.image_url = form.image_url.data
        project.external_link = form.external_link.data  # ← updated here
        project.category = form.category.data
        db.session.commit()
        flash('Project updated successfully!', 'success')
        return redirect(url_for('main.admin_projects'))

    elif request.method == 'GET':
        form.title.data = project.title
        form.description.data = project.description
        form.image_url.data = project.image_url
        form.external_link.data = project.external_link  # ← updated here
        form.category.data = project.category

    return render_template('admin_edit_project.html', form=form, project=project)



@main.route('/admin/projects/delete/<int:project_id>')
@login_required
def delete_project(project_id):
    if current_user.email != 'admin@example.com':
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('main.home'))

    project = Project.query.get_or_404(project_id)
    db.session.delete(project)
    db.session.commit()
    log_event(f"Admin {current_user.email} deleted project ID {project_id}")
    flash('Project deleted.', 'info')
    return redirect(url_for('main.admin_projects'))

@main.route('/admin/logs')
@login_required
def view_logs():
    if current_user.email != 'admin@example.com':
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('main.home'))

    try:
        with open('security.log', 'r') as log_file:
            # Show last 50 lines (adjust as needed)
            lines = log_file.readlines()[-50:]
    except FileNotFoundError:
        lines = ['No logs found.']

    return render_template('view_logs.html', logs=lines)


@main.route('/about')
def about_me():
    return render_template('about.html')


@main.route('/admin/metrics')
@login_required
def security_metrics():
    if current_user.email != 'admin@example.com':
        flash('Access denied.', 'danger')
        return redirect(url_for('main.home'))

    log_path = 'security.log'
    if not os.path.exists(log_path):
        return render_template('metrics.html', metrics=None)

    with open(log_path, 'r') as f:
        logs = f.readlines()

    success_logins = [line for line in logs if "Successful login" in line]
    failed_logins = [line for line in logs if "Failed login" in line]
    registered = [line for line in logs if "New user registered" in line]

    all_attempts = success_logins + failed_logins
    latest_entry = logs[-1] if logs else "No activity yet."

    unique_users = set()
    for line in success_logins:
        if "login:" in line:
            email = line.split("login: ")[1].strip()
            unique_users.add(email)

    metrics = {
        "total_attempts": len(all_attempts),
        "successful_logins": len(success_logins),
        "failed_logins": len(failed_logins),
        "registered_users": len(registered),
        "unique_logins": len(unique_users),
        "last_event": latest_entry.strip()
    }

    return render_template('metrics.html', metrics=metrics)

@main.route('/tools/headers', methods=['GET', 'POST'])
@login_required
def header_analyzer():
    headers_result = None
    error = None

    if request.method == 'POST':
        url = request.form.get('url')
        if not url.startswith('http'):
            url = 'https://' + url  # assume HTTPS

        try:
            response = requests.get(url, timeout=5)
            headers_result = dict(response.headers)
        except Exception as e:
            error = str(e)

    return render_template('tools_headers.html', headers=headers_result, error=error)

@main.route('/tools/jwt', methods=['GET', 'POST'])
@login_required
def jwt_decoder():
    decoded = {}
    error = None

    if request.method == 'POST':
        token = request.form.get('jwt_token')

        try:
            # Split JWT manually
            parts = token.split('.')
            if len(parts) != 3:
                raise ValueError("Invalid JWT structure (must have 3 parts).")

            def decode_part(part):
                padded = part + '=' * (-len(part) % 4)
                return json.loads(base64.urlsafe_b64decode(padded))

            decoded = {
                "header": decode_part(parts[0]),
                "payload": decode_part(parts[1]),
                "signature": parts[2]
            }
        except Exception as e:
            error = str(e)

    return render_template('tools_jwt.html', decoded=decoded, error=error)

@main.route('/tools/threat-sim', methods=['GET', 'POST'])
@login_required
def threat_sim():
    result = None
    error = None

    if request.method == 'POST':
        user_input = request.form.get('sim_input')

        # Simulated threat detection
        threats = ['<script>', 'DROP TABLE', 'SELECT * FROM', '1=1', '--', ' OR ', ';', '<?php']
        detected = [t for t in threats if t.lower() in user_input.lower()]

        if detected:
            result = f"🚨 Threat simulation detected: {', '.join(detected)}"
            current_app.logger.info(f"Simulated threat input from {current_user.email}: {user_input}")
        else:
            result = "✅ Input is clean. No threats detected."

    return render_template('tools_threat_sim.html', result=result, error=error)