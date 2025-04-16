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
    if current_user.email != 'admin@example.com':
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('main.home'))

    form = ProjectForm()
    if form.validate_on_submit():
        project = Project(
            title=form.title.data,
            description=form.description.data,
            image_url=form.image_url.data or None,
            project_url=form.project_url.data or None
        )
        db.session.add(project)
        db.session.commit()
        log_event(f"Admin {current_user.email} added project: {form.title.data}")
        flash('Project added successfully!', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('add_project.html', form=form)


@main.route('/projects')
def projects():
    all_projects = Project.query.all()
    return render_template('projects.html', projects=all_projects)


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
    if current_user.email != 'admin@example.com':
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('main.home'))

    project = Project.query.get_or_404(project_id)
    form = ProjectForm()

    if form.validate_on_submit():
        project.title = form.title.data
        project.description = form.description.data
        project.image_url = form.image_url.data
        project.project_url = form.project_url.data
        db.session.commit()
        log_event(f"Admin {current_user.email} edited project ID {project_id}")
        flash('Project updated successfully!', 'success')
        return redirect(url_for('main.admin_projects'))

    # Pre-fill the form with current data
    form.title.data = project.title
    form.description.data = project.description
    form.image_url.data = project.image_url
    form.project_url.data = project.project_url

    return render_template('edit_project.html', form=form, project=project)


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
