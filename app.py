from flask import Flask, render_template, session, redirect, request, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3
import re

app = Flask(__name__, template_folder = 'templates')
app.secret_key = 'buroak'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/udyding/Desktop/bossdeca/executives.db'

conn = sqlite3.connect('/Users/udyding/Desktop/bossdeca/executives.db', check_same_thread=False)
db = conn.cursor()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('id') is None:
            return redirect('/')
        return f(*args, **kwargs)
    return decorated_function


"""PROFILE"""

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        session.clear() #removes user id if there is one already in the session
        if not request.form.get('username'):
            flash('Please enter a username')
            return render_template('login.html')
        elif not request.form.get('password'):
            flash('Please enter a password')
            return render_template('login.html')

        db.execute('SELECT * FROM executives where username = ?', (request.form.get('username'),))
        rows = db.fetchall()

        if len(rows) != 1 or not check_password_hash(rows[0][7], (request.form.get('password'))):
            flash('Username or password is incorrect.')
            return render_template('login.html')
        else:
            session['id'] = rows[0][0]
            return redirect('/dashboard')

    return render_template('login.html')


@app.route('/changepassword', methods=['GET', 'POST'])
@login_required
def changepassword():
    if request.method == 'POST':
        db.execute('SELECT hashed_password FROM executives WHERE id = ?', (session['id'], ))
        user_info = db.fetchall()
        current_password = user_info[0][0]

        if not request.form.get('old_password') or not check_password_hash(current_password, request.form.get('old_password')):
            flash("Old password is incorrect.")
            return render_template('changepassword.html')
        elif len(request.form.get('new_password')) < 8:
            flash("Password must be at least 8 characters long and contain a number.")
            return render_template('changepassword.html')
        elif not re.search('\d', request.form.get('new_password')):
            flash("Password must be at least 8 characters long and contain a number.")
            return render_template('changepassword.html')
        elif not request.form.get('new_password'):
            flash("Please enter a new password.")
            return render_template('changepassword.html')
        elif not request.form.get('confirm_password'):
            flash("Please confirm your new password.")
            return render_template('changepassword.html')
        elif request.form.get('confirm_password') != request.form.get('new_password'):
            flash("New passwords do not match.")
            return render_template('changepassword.html')
        
        new_hashed_password = generate_password_hash(request.form.get('new_password'))
        db.execute('UPDATE executives SET hashed_password = ? WHERE id = ?', (new_hashed_password, session['id']))
        conn.commit()

        flash('Password has been successfully updated')

        return redirect('/dashboard')
    return render_template('changepassword.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect('/')


@app.route('/dashboard')
@login_required
def dashboard():
    db.execute('SELECT first_name, last_name, role FROM executives WHERE id = ?', (session['id'], ))
    info = db.fetchall()
    user_info = {
        'first_name': info[0][0],
        'last_name': info[0][1],
        'role': info[0][2]
    }


    return render_template('dashboard.html', user_info=user_info)

@app.route('/chapter')
@login_required
def chapter():
    return render_template('chapter.html')

@app.route('/mystudents')
@login_required
def mystudents():
    return render_template('mystudents.html')

@app.route('/mystudents/<student>')
@login_required
def student():
    return render_template()

@app.route('/training')
@login_required
def training():
    return render_template('training.html')

@app.route('/resources')
@login_required
def resources():
    return render_template('resources.html')

@app.route('/resources/events')
@login_required
def events():
    return render_template('events.html')

@app.route('/resources/minutes')
@login_required
def minutes():
    return render_template('minutes.html')

#made just to register execs for the first time and generate hashed pass, will be hidden, no authentication
@app.route('/signup', methods=['GET', 'POST'])
@login_required
def signup():
    if request.method == 'POST':
        db.execute('INSERT into executives (id, username, first_name, last_name, role, email, hashed_password) VALUES (?, ?, ?, ?, ?, ?, ?)', (
            request.form.get('id'), request.form.get('username'), request.form.get('first_name'),
            request.form.get('last_name'), request.form.get('role'), request.form.get('email'), generate_password_hash(request.form.get('password'))
        ))
        conn.commit()
    return render_template('signup.html')

if __name__ == "__main__":
    app.run(debug=True)