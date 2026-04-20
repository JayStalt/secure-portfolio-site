from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from app import db, bcrypt
from app.main import bp as main
from app.models import Project, User
from app.forms import LoginForm, RegisterForm, ProjectForm


# ----------------------
# HOME
# ----------------------
@main.route('/')
@main.route('/index')
def index():
    return render_template('index.html')


# ----------------------
# ABOUT
# ----------------------
@main.route('/about')
def about():
    return render_template('about.html')


# ----------------------
# PROJECTS
# ----------------------
@main.route('/projects')
def projects():
    cyber = Project.query.filter_by(category='cyber').all()
    fullstack = Project.query.filter_by(category='fullstack').all()

    gamedev = Project.query.filter(
        Project.category.in_(['games', 'gamedev'])
    ).all()

    gamedesign = Project.query.filter_by(category='gamedesign').all()
    webdesign = Project.query.filter_by(category='webdesign').all()
    writing = Project.query.filter_by(category='writing').all()

    return render_template(
        'projects_tabs.html',
        cyber=cyber,
        fullstack=fullstack,
        gamedev=gamedev,
        gamedesign=gamedesign,
        webdesign=webdesign,
        writing=writing
    )


# ----------------------
# LOGIN
# ----------------------
@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('main.index'))
        else:
            flash('Invalid email or password', 'danger')

    return render_template('login.html', form=form)


# ----------------------
# LOGOUT
# ----------------------
@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))


# ----------------------
# REGISTER
# ----------------------
@main.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    form = RegisterForm()

    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=hashed_pw
        )
        db.session.add(user)
        db.session.commit()

        flash('Account created successfully!', 'success')
        return redirect(url_for('main.login'))

    return render_template('register.html', form=form)


# ----------------------
# ADMIN: VIEW PROJECTS
# ----------------------
@main.route('/admin/projects')
@login_required
def admin_projects():
    projects = Project.query.all()
    return render_template('admin_projects.html', projects=projects)


# ----------------------
# ADMIN: ADD PROJECT
# ----------------------
@main.route('/admin/projects/new', methods=['GET', 'POST'])
@login_required
def add_project():
    form = ProjectForm()

    if form.validate_on_submit():
        project = Project(
            title=form.title.data,
            description=form.description.data,
            image_url=form.image_url.data,
            external_link=form.external_link.data,
            category=form.category.data
        )

        db.session.add(project)
        db.session.commit()

        flash('Project added successfully!', 'success')
        return redirect(url_for('main.admin_projects'))

    return render_template('admin_add_project.html', form=form)


# ----------------------
# ADMIN: EDIT PROJECT
# ----------------------
@main.route('/admin/projects/edit/<int:project_id>', methods=['GET', 'POST'])
@login_required
def edit_project(project_id):
    project = Project.query.get_or_404(project_id)
    form = ProjectForm()

    if form.validate_on_submit():
        project.title = form.title.data
        project.description = form.description.data
        project.image_url = form.image_url.data
        project.external_link = form.external_link.data
        project.category = form.category.data

        db.session.commit()
        flash('Project updated successfully!', 'success')
        return redirect(url_for('main.admin_projects'))

    elif request.method == 'GET':
        form.title.data = project.title
        form.description.data = project.description
        form.image_url.data = project.image_url
        form.external_link.data = project.external_link
        form.category.data = project.category

    return render_template('admin_edit_project.html', form=form, project=project)


# ----------------------
# ADMIN: DELETE PROJECT
# ----------------------
@main.route('/admin/projects/delete/<int:project_id>')
@login_required
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)

    db.session.delete(project)
    db.session.commit()

    flash('Project deleted.', 'info')
    return redirect(url_for('main.admin_projects'))