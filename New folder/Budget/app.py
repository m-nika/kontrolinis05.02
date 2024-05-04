from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import DateTime
import os
import forms
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from datetime import datetime
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView


basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + \
    os.path.join(basedir, 'sqlite.db')
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
admin = Admin(app)

login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.login_message = 'Log in to see this page.'

class AdminModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.username == "admin"


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(50), unique=True, nullable=False)


class Entry(db.Model):
    __tablename__ = 'entries'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(DateTime, default=datetime.now())
    income = db.Column(db.Boolean)
    sum = db.Column(db.Float)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship('User', lazy=True)


admin.add_view(AdminModelView(User, db.session))
admin.add_view(AdminModelView(Entry, db.session))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


with app.app_context():
    db.create_all()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = forms.RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(
            form.password.data).decode('utf-8')
        user = User(name=form.name.data, email=form.email.data,
                    password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('You have successfully registered! You can now log in.', 'success')
        return redirect(url_for('index'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = forms.LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Email or password is incorrect.', 'danger')
    return render_template('login.html', form=form)


@app.route('/new_entry', methods=['GET', 'POST'])
@login_required
def new_entry():
    form = forms.EntryForm()
    if form.validate_on_submit():
        income = True if form.income.data else False

        amount = form.sum.data if income else -form.sum.data

        new_entry = Entry(income=income, sum=amount, user_id=current_user.id)
        db.session.add(new_entry)
        db.session.commit()

        flash('Entry was created successfully', 'success')
        return redirect(url_for('entries'))
    return render_template('new_entry.html', form=form)


@app.route('/entries')
@login_required
def entries():
    my_entries = Entry.query.filter_by(user_id=current_user.id).all()
    return render_template('entries.html', my_entries=my_entries)


@app.route('/all_entries')
@login_required
def all_entries():
    all_entries = Entry.query.all()
    return render_template('all_entries.html', all_entries=all_entries)


@app.route('/account')
@login_required
def account():
    return render_template('account.html')


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = forms.ProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('profile'))
    elif request.method == 'GET':
        form.name.data = current_user.name
        form.email.data = current_user.email
    return render_template('profile.html', form=form)



@app.route('/balance')
@login_required
def balance():
    all_entries = Entry.query.filter_by(user_id=current_user.id)
    balance = 0
    for entry in all_entries:
        if entry.income:
            balance += entry.sum
        else:
            balance -= entry.sum
    return render_template('balance.html', balance=balance)


@app.route('/delete/<id>')
@login_required
def delete(id):
    entry = Entry.query.get(id)
    if entry.user_id != current_user.id:
        return redirect(url_for('index'))
    db.session.delete(entry)
    db.session.commit()
    return redirect(url_for('entries'))


@app.route('/update/<id>', methods=['GET', 'POST'])
@login_required
def update(id):
    entry = Entry.query.get(id)
    if entry.user_id != current_user.id:
        return redirect(url_for('index'))
    form = forms.EntryForm()
    if form.validate_on_submit():
        print(form.sum.data)
        entry.sum = form.sum.data
        entry.income = form.income.data
        db.session.commit()
        flash('You have updated entry successfully', 'success')
        return redirect(url_for('entries'))
    elif request.method == 'GET':
        form.sum.data = entry.sum
        form.income.data = entry.income
    return render_template('update.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8000, debug=True)
