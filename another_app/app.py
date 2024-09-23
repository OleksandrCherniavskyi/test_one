from datetime import datetime
from flask_login import UserMixin
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import re
from flask_sqlalchemy import SQLAlchemy


# Create Flask app
app = Flask(__name__)

# Configure the app
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy()

import os
SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY

# Initialize SQLAlchemy with the app
db.init_app(app)


# Create the tables inside the app context
with app.app_context():
    class User(db.Model, UserMixin):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(50), nullable=False, unique=True)
        password = db.Column(db.String(255), nullable=False)
        email = db.Column(db.String(100), nullable=False, unique=True)


    class Task(db.Model):
        id_task = db.Column(db.Integer, primary_key=True)
        task_title = db.Column(db.String(120), nullable=False)
        task_status = db.Column(db.Boolean, default=False)
        id_users = db.Column(db.Integer, db.ForeignKey('user.id'))


    class TaskComment(db.Model):
        id_taskcomment = db.Column(db.Integer, primary_key=True)
        id_task = db.Column(db.Integer, db.ForeignKey('task.id_task'))
        datetime = db.Column(db.DateTime, nullable=False)
        comment = db.Column(db.Text)


# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Import the User model (this should be in your models.py)




@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']

        # Query the account from the SQLite database using the User model
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            # If account exists and password is correct
            login_user(user)
            session['loggedin'] = True
            session['id'] = user.id
            session['username'] = user.username
            msg = 'Logged in successfully!'
            return render_template('task_list.html', msg=msg)
        else:
            msg = 'Incorrect username / password!'
    return render_template('login.html', msg=msg)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # Check if username or email already exists
        user = User.query.filter_by(username=username).first()
        if user:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers!'
        elif not username or not password or not email:
            msg = 'Please fill out the form!'
        else:
            # Hash the password with pbkdf2:sha256
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(username=username, password=hashed_password, email=email)
            db.session.add(new_user)
            db.session.commit()
            msg = 'You have successfully registered!'
    elif request.method == 'POST':
        msg = 'Please fill out the form!'
    return render_template('register.html', msg=msg)


@app.route('/task_list', methods=['GET', 'POST'])
@login_required
def task_list():
    user_id = current_user.id

    tasks = Task.query.filter_by(id_users=user_id).all()

    if request.method == 'POST':
        task_title = request.form['task_title']
        task_comment = request.form['task_comment']

        new_task = Task(task_title=task_title, task_status=False, id_users=user_id)
        db.session.add(new_task)

        db.session.commit()

        # Automatic comment for task creation
        auto_comment = TaskComment(id_task=new_task.id_task, datetime=datetime.now(), comment="Task created")
        db.session.add(auto_comment)

        # User comment (if provided)
        if task_comment:
            user_comment = TaskComment(id_task=new_task.id_task, datetime=datetime.now(), comment=task_comment)
            db.session.add(user_comment)

        db.session.commit()

        return redirect(url_for('task_list'))

    return render_template('task_list.html', tasks=tasks)

@app.route('/task_detail/<int:task_id>', methods=['GET', 'POST'])
@login_required
def task_detail(task_id):
    task = Task.query.get_or_404(task_id)

    # Uncomment this line if you want to enforce authorization
    # if task.id_users != current_user.id:
    #     abort(403)  # Unauthorized access

    # Retrieve open comments for the task
    open_comments = db.session.query(TaskComment).join(Task).filter(Task.task_status == 1, TaskComment.id_task == task.id_task).all()

    if request.method == 'POST':
        if 'task_status' in request.form:
            task.task_status = not task.task_status
            db.session.commit()
            flash('Task status updated successfully!', 'success')
        elif 'task_comment' in request.form:
            comment = TaskComment(id_task=task.id_task, datetime=datetime.now(), comment=request.form['task_comment'])
            db.session.add(comment)
            db.session.commit()
            flash('Comment added successfully!', 'success')

        return redirect(url_for('task_detail', task_id=task.id_task))

    return render_template('task_detail.html', task=task, open_comments=open_comments)


if __name__ == '__main__':
    app.run(debug=True)