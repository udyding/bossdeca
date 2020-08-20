from flask import Flask, render_template, session, redirect, request, url_for, g, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

class User:
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

    def __repr__(self):
        return f'<User: {self.username}>'


app = Flask(__name__, template_folder = 'templates')
app.secret_key = 'poopoo'

conn = sqlite3.connect('/Users/udyding/Desktop/bossdeca/executives.db', check_same_thread=False)
db = conn.cursor()


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

        username = request.form['username']
        password = request.form['password']

        db.execute('SELECT * from USERS where username = ?', username=username)
        rows = db.fetchall()

        if len(rows) != 1 or not 
        user = [x for x in users if x.username == username][0]
                
        if user and user.password == password:
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
            return redirect(url_for('login'))
    return render_template('login.html')
            #FIX AUTHENTICATION TO DISPLAY ERROR MESSAGE IF USERNAME AND PASSWORD DONT MATCH AT ALL
            #ADD MESSAGE FLASHING
            #NEED TO ALLOW USERS TO SIGN UP TO ALLOW THEM TO CREATE OWN PASSWORDS PLUS HASH

#only used to create hashed passwords
@app.route('/changepassword', method=['GET', 'POST'])
def changepassword():
    return render_template('changepassword.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if not g.user:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

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

if __name__ == "__main__":
    app.run(debug=True)