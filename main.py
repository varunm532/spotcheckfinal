import threading
import sqlite3

# import "packages" from flask
from flask import render_template,render_template, url_for, redirect,request  # import render_template from "public" flask libraries
from flask.cli import AppGroup


# import "packages" from "this" project
from __init__ import app, db, cors  # Definitions initialization


# setup APIs
from api.user import user_api # Blueprint import api definition
from api.player import player_api
# database migrations
from model.users import initUsers
from model.players import initPlayers
from flask_login import  LoginManager, login_user, logout_user, login_required, UserMixin
from flask_bcrypt import Bcrypt

# setup App pages
from projects.projects import app_projects # Blueprint directory import projects definition


# Initialize the SQLAlchemy object to work with the Flask app instance
db.init_app(app)

# register URIs
app.register_blueprint(user_api) # register api routes
app.register_blueprint(player_api)
app.register_blueprint(app_projects) # register app pages

login_manager = LoginManager(app)
bcrypt = Bcrypt(app)

@app.errorhandler(404)  # catch for URL not found
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('404.html'), 404

@app.route('/')  # connects default URL to index() function
def index():
    return render_template("index.html")

@app.route('/table/')  # connects /stub/ URL to stub() function
def table():
    return render_template("table.html")

@app.route('/register', methods=['GET', 'POST'])
def login():
    # Define your site variable here
    site = {'baseurl': 'http://localhost:8086'}
    return render_template('login.html', site=site)

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    # Define your site variable here
    site = {'baseurl': 'http://localhost:8086'}
    return render_template('signin.html', site=site)

@app.route('/display/', methods=['GET'])
def display():
    site = {'baseurl': 'http://localhost:8086'}
    ##return render_template('getusers.html', site=site)
    return render_template('displayusers.html', site=site)

@app.route('/login1', methods=['GET', 'POST'])
def login1():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = user_api.query.filter_by(uid=username).first()

        #if user and bcrypt.check_password_hash(user.password, password):
        if user and  (user._password == password):
            login_user(user)
            return redirect(url_for('welcome'))

    return render_template('login1.html')
class User(UserMixin):
    def __init__(self, uid, password):
        self.uid = uid
        self._password = password

    def get_id(self):
        return str(self.uid)

# Set up Flask-Login
login_manager = LoginManager(app)

@login_manager.user_loader
def load_user(uid):
    # Return the user object based on the user_id
    return User.query.get(int(uid))

# @app.route('/display/')
# def display():
#     return render_template("displayusers.html")

@app.before_request
def before_request():
    # Check if the request came from a specific origin
    allowed_origin = request.headers.get('Origin')
    if allowed_origin in ['http://localhost:4100', 'http://127.0.0.1:4100', 'https://nighthawkcoders.github.io']:
        cors._origins = allowed_origin

# Create an AppGroup for custom commands
custom_cli = AppGroup('custom', help='Custom commands')

# Define a command to generate data
@custom_cli.command('generate_data')
def generate_data():
    initUsers()
    initPlayers()

# Register the custom command group with the Flask application
app.cli.add_command(custom_cli)
        
# this runs the application on the development server
if __name__ == "__main__":
    # change name for testing
    app.run(debug=True, host="0.0.0.0", port="8086")