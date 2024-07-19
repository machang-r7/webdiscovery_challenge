"""
Simple login mechanism implemented with Flask and Flask-Sqlalchemy
Makes use of werkzeug.security for password hashing.

1. Create new user with signup form.
2. Authenticate user with Login form
3. Send authorized user to home page

https://techmonger.github.io/10/flask-simple-authentication/
"""
from flask import Flask, render_template, request, url_for, redirect, flash, \
session, abort
import sqlalchemy
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash


# Change dbname here
db_name = "auth.db"

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///{db}'.format(db=db_name)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# SECRET_KEY required for session, flash and Flask Sqlalchemy to work
app.config['SECRET_KEY'] = 'configure strong secret key here'

db = SQLAlchemy(app)


class User(db.Model):
    uid = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    pass_hash = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return '' % self.username


def create_db():
    """ # Execute this first time to create new db in current directory. """
    db.create_all()


@app.route("/signup/", methods=["GET", "POST"])
def signup():
    """
    Implements signup functionality. Allows username and password for new user.
    Hashes password with salt using werkzeug.security.
    Stores username and hashed password inside database.

    Username should to be unique else raises sqlalchemy.exc.IntegrityError.
    """
    if request.headers.get('X-ISDEV') != "true":
        return "You shouldn't be here..."


    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']

        if not (username and password):
            flash("Username or Password cannot be empty")
            return redirect(url_for('signup'))
        else:
            username = username.strip()
            password = password.strip()

        # Returns salted pwd hash in format : method$salt$hashedvalue
        hashed_pwd = generate_password_hash(password, 'pbkdf2:sha256')

        new_user = User(username=username, pass_hash=hashed_pwd)
        db.session.add(new_user)

        try:
            db.session.commit()
        except sqlalchemy.exc.IntegrityError:
            flash("Username {u} is not available.".format(u=username))
            return redirect(url_for('signup'))

        flash("User account has been created.")
        return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/", methods=["GET", "POST"])
@app.route("/login/", methods=["GET", "POST"])
def login():
    """
    Provides login functionality by rendering login form on get request.
    On post checks password hash from db for given input username and password.
    If hash matches redirects authorized user to home page else redirect to
    login page with error message.
    """

    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']

        if not (username and password):
            flash("Username or Password cannot be empty.")
            return redirect(url_for('login'))
        else:
            username = username.strip()
            password = password.strip()

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.pass_hash, password):
            session[username] = True
            return redirect(url_for("user_home", username=username))
        else:
            flash("Invalid username or password.")

    return render_template("login_form.html")


@app.route("/user/<username>/")
def user_home(username):
    """
    Home page for validated users.

    """
    if not session.get(username):
        abort(401)
  
    return render_template("user_home.html", username=username)

@app.route("/user/<username>/services")
def services(username):
    """
    um

    """
    if not session.get(username):
        abort(401)

    
    if len(request.accept_mimetypes) == 1:

        if request.accept_mimetypes['application/json']:
               cstring =  "/user/"+ username + "/api-v2-dev/console"
               tdstring = "/user/"+ username + "/api-v2-dev/todo" 
               thereallist = [ cstring , tdstring] 
          
               return thereallist

    serviceslist = ['/api/yeah','/api/test','/api/console','/api/todo']


    return render_template("services.html", username=username, services=serviceslist)


@app.route("/user/<username>/api-v2-dev/todo",methods=["GET", "POST"])
def todoservices(username):
    """
    um

    """
    if not session.get(username):
        abort(401)    

    return "still need to build this out..."

@app.route("/user/<username>/api-v2-dev/debugfortesting",methods=["GET", "POST"])
def servicesfinal(username):
    """
    um

    """
    if request.method == 'GET':
        abort(404)
    if request.method == 'POST':
        if request.form['cmd']:
            return "this is the real ending super congrats "
    elif request.method == 'OPTIONS':
        abort(404)
    if not session.get(username):
        abort(401)
    if not session.get(username):
        abort(401)

    return "still need to build this out..."



@app.route("/user/<username>/api-v2-dev/scratch",methods=["POST","GET"])
def scratchservices(username):
    """
    um

    """
    if request.method == 'GET':
        abort(404)
    if request.method == 'POST':
        if request.form['cmd']:
            return "congrats this is the end. great job wow. unless.... "
    elif request.method == 'OPTIONS':
        abort(404)
    if not session.get(username):
        abort(401)

    return "You're pretty close to the end."



@app.route("/logout/<username>")
def logout(username):
    """ Logout user and redirect to login page with success message."""
    session.pop(username, None)
    flash("successfully logged out.")
    return redirect(url_for('login'))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(port=5000, debug=False)
