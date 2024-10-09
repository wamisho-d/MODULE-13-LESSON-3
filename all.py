# Task 1: Define User Model
from werkzeug.securt import generate_password_hash, check_password_hash
from flask_sqlalchemy import AQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False) # Example roles: 'admin', 'user'

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)
    
# Task 2: Implement JWT Token Generation
# Add the pyjwt dependency in requirements.txt:
Flask 
SQLAlchemy
pyjwt==2.4.0


# Create the utils/util.py file for handling token generation and validation:

import jwt
import datetime
from flask import current_app

def encode_token(user_id):
    """
    Generates the JWT token for a given user_id.
    """

    try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1), # Token expires after 1 day
            'iat': datetime.datetime.utcnow(),
            'sub': user_id

        }
        return jwt.encode(
            payload,
            current_app.config.get('SECRET_KEY'),
            algorithm='HS256'
        )
    except Exception as e:
        return str(e)
def decode_token(token):
    """
    Validates and decodes the JWT token.
    """
    try:
        payload = jwt.decode(token, current_app.config.get('SECRET_KEY'), algorithms=['HS256'])
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return 'Token expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again'
    
#In your main app configuration, add the secret key for signing the JWT tokens (this should be kept secure):

import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key') # Make sure to set a secure key in production

# Task 3: Authentication Logic
# Create a login function to authenticate users and generate a JWT token:
from flask import request, jsonify
from .models import User
from .utils.util import encode_token

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        token = encode_token(user.id)
        return jsonify({
            'message': 'Login sucessful',
            'token': token
        }), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

# Create the controller to manage JWT tokens in requests:
from flask import request

def get_token_from_headers():
    token = request.headers.get('Authorization')
    if token and token.startswith('Bearer'):
        return token.split(" ")[1]
    return None

# Task 4: Implement Role-based Access Control
from functools import wraps
from flask import request, jsonify
from .models import User
from .utils.util import decode_token

def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = get_token_from_headers()
            if token:
                user_id = decode_token(token)
                user = User.query.get(user_id)
                if user and user.role == required_role:
                    return f(*args, **kwargs)
                else:
                    return jsonify({'message': 'You do not have permission to access this resource.'}), 403
            else:
            
                return jsonify({'message': 'Token is missing or invalid'}), 401
        return decorated_function
    return decorator

# Apply this decorator to sensitive endpoints, such as creating or managing factory data:
@app.route('/create_order', methods=['POST'])
@role_required('admin')
def create_order():
    # Only admins can create orders
    # Order creation logic
    return jsonify({'message': 'Order created sucessfully'}), 201
                

                
    
    
    
