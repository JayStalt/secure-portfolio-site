from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from app.models import User  # Make sure this import is at the top of forms.py
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That Username is already taken.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already registered.')


class ProjectForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=2, max=100)])
    description = TextAreaField('Description', validators=[DataRequired()])
    image_url = StringField('Image URL (optional)')
    project_url = StringField('Project Link (optional)')
    category = SelectField('Category', choices=[
        ('cyber', 'Cyber'),
        ('fullstack', 'Full Stack Dev'),
        ('games', 'Games'),
        ('writing', 'Creative Writing')
    ], validators=[DataRequired()])
    submit = SubmitField('Add Project')
