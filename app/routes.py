from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.main import bp as main
from app.models import Project, User
from app.forms import LoginForm, ProjectForm


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
# PROJECTS (FIXED VERSION)
# ----------------------
@main.route('/projects')
def projects():
    cyber = Project.query.filter_by(category='cyber').all()
    fullstack = Project.query.filter_by(category='fullstack').all()

    # SAFE: supports old + new category
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
# LOGIN (Metrics Only)
# ----------------------
@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('main.login'))

        login_user(user)
        return redirect(url_for('main.index'))

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
# ADD PROJECT (ADMIN)
# ----------------------
@main.route('/add_project', methods=['GET', 'POST'])
@login_required
def add_project():
    form = ProjectForm()

    if form.validate_on_submit():
        project = Project(
            title=form.title.data,
            description=form.description.data,
            category=form.category.data,
            image_url=form.image_url.data,
            external_link=form.external_link.data
        )

        db.session.add(project)
        db.session.commit()

        flash('Project added successfully!')
        return redirect(url_for('main.projects'))

    return render_template('add_project.html', form=form)