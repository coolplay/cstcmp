#coding: utf-8
import os
from flask import Flask, render_template, flash, redirect, url_for, session, abort, request, \
    current_app
from flask.ext.bootstrap import Bootstrap
from flask.ext.wtf import Form
from wtforms import StringField, PasswordField, SelectField, BooleanField, SubmitField
from wtforms import ValidationError
from wtforms.validators import Required, Email, EqualTo
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager, UserMixin
from flask.ext.login import login_user, logout_user, login_required, current_user
from flask.ext.mail import Mail, Message
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer


app = Flask(__name__)

bootstrap = Bootstrap(app)
app.config['BOOTSTRAP_SERVE_LOCAL'] = True

dbpath = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'data.db')
app.config['SECRET_KEY'] = 'I will not tell'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///{}'.format(dbpath)
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# XXX smtp.qq.com:587 failed with SSL.
app.config['MAIL_SERVER'] = 'smtp.qq.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_DEFAULT_SENDER'] = app.config['MAIL_USERNAME']
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
mail = Mail(app)

def send_email(to, subject, template=None, body=None, **kwargs):
    if not isinstance(to, list):
        to = [to]
    msg = Message(subject='[cstcmp] {}'.format(subject), recipients=to)
    if template:
        msg.body = render_template(template, **kwargs)
    elif body:
        msg.body = body
    else:
        msg.body = 'This is the default body text'
    print msg.as_string()
    mail.send(msg)


@app.route('/email')
def email():
    to = app.config['MAIL_USERNAME']
    body = request.args.get('body')
    send_email(to, 'Hello there', body=body)
    flash('sent')
    return redirect(url_for('index'))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class RegisterForm(Form):
    email = StringField('Email', validators=[Required(), Email()])
    password = PasswordField('Password', validators=[Required(), EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm Password', validators=[Required()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')
            pass


class LoginForm(Form):
    username = StringField('Username', validators=[Required()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Remember me')
    submit = SubmitField('Login')


class EditProfileForm(Form):
    name = StringField('Name', validators=[Required()])
    gender = SelectField('Gender', choices=[('0', 'Male'), ('1', 'Female')])
    organization = StringField('Organization', validators=[Required()])
    title = SelectField('Title', choices=[('0', u'本科'), ('1', u'研究生')])
    mobile = StringField('Phone number', validators=[Required()])
    address = StringField('Address', validators=[Required()])
    postcode = StringField('Postcode')
    submit = SubmitField('Save')


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True)
    password = db.Column(db.String(64))
    #XXX input exceeds length error
    name = db.Column(db.String(64))
    gender = db.Column(db.String(64))
    organization = db.Column(db.String(64))
    title = db.Column(db.String(64))
    mobile = db.Column(db.String(64))
    address = db.Column(db.String(64))
    postcode = db.Column(db.String(64))
    confirmed = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return '<User {} {}>'.format(self.email)

    def generate_confirmation_token(self, expiration=3600):
        #XXX why not app.config?
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.id})

    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except Exception:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True


@app.route('/')
def index():
    if current_user.is_authenticated and not current_user.confirmed:
        flash('Please confirm your account in your inbox')
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.username.data, password=form.password.data).first()
        if user:
            login_user(user, form.remember_me.data)
            flash(u'You are logged in as {}'.format(current_user.email))
            return redirect(request.args.get('next') or url_for('index'))
        flash('Invalid account.')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('{}'.format(session))
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(email=form.email.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email(user.email, 'Confirm your account', body=url_for('confirm', token=token, _external=True))
        flash('A confirmation email has been sent to your account: {}!'.format(form.email.data))
        return redirect(url_for('index'))
    return render_template('register.html', form=form)


@app.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('index'))
    if current_user.confirm(token):
        flash('Account has been confirmed.')
    else:
        flash('Token invalid or expires.')
    return redirect(url_for('index'))


@app.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        flash('No need to confirm.')
        return redirect(url_for('index'))
    return render_template('unconfirmed.html')


@app.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'Confirm your account', body=url_for('confirm', token=token, _external=True))
    flash('A new confirmation email has been sent to your account: {}!'.format(current_user.email))
    return redirect(url_for('index'))


@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.gender = form.gender.data
        current_user.organization = form.organization.data
        current_user.title = form.title.data
        current_user.mobile = form.mobile.data
        current_user.address = form.address.data
        current_user.postcode = form.postcode.data
        flash('Profile modified.')
        db.session.add(current_user)
        return redirect(url_for('edit_profile'))
    form.name.data = current_user.name
    form.gender.data = current_user.gender
    form.organization.data = current_user.organization
    form.title.data = current_user.title
    form.mobile.data = current_user.mobile
    form.address.data = current_user.address
    form.postcode.data = current_user.postcode
    return render_template('edit_profile.html', form=form)


@app.route('/query')
def query():
    if session.get('name') != 'hello@gmail.com':
        abort(403)
    users = User.query.all()
    return render_template('query.html', users=users)


if __name__ == '__main__':
    app.run()
