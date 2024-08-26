from flask import Flask, request, redirect, render_template, jsonify, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import string
import random
from urllib.parse import urlparse
import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///urls.db'
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a random secret key
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    urls = db.relationship('URL', backref='user', lazy=True)

class URL(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original = db.Column(db.String(500), nullable=False)
    short = db.Column(db.String(6), unique=True, nullable=False)
    clicks = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_short_url():
    characters = string.ascii_letters + string.digits
    while True:
        short_url = ''.join(random.choice(characters) for i in range(6))
        if not URL.query.filter_by(short=short_url).first():
            return short_url

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        original_url = request.form['url']
        if not is_valid_url(original_url):
            return jsonify({"error": "Invalid URL. Please enter a valid URL including http:// or https://"})
        
        if current_user.is_authenticated:
            short_url = generate_short_url()
            new_url = URL(original=original_url, short=short_url, user=current_user)
            db.session.add(new_url)
            db.session.commit()
            return jsonify({"short_url": f"{request.host_url}{short_url}"})
        else:
            return jsonify({"error": "Please log in to shorten URLs"})
    return render_template('index.html')

@app.route('/<short_url>')
def redirect_to_url(short_url):
    url_record = URL.query.filter_by(short=short_url).first_or_404()
    url_record.clicks += 1
    db.session.commit()
    return redirect(url_record.original)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({"error": "Username already exists"})
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "Registration successful. Please log in."})
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return jsonify({"message": "Login successful"})
        return jsonify({"error": "Invalid username or password"})
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')

@app.route('/dashboard')
@login_required
def dashboard():
    urls = URL.query.filter_by(user=current_user).all()
    return render_template('dashboard.html', urls=urls)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)