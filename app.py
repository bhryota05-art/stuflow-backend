import os
from flask import Flask, request, jsonify, g, render_template, send_from_directory
from datetime import datetime, timedelta
import jwt
import random
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from dotenv import load_dotenv
import uuid

load_dotenv()

app = Flask(__name__)
CORS(app)

# ========== DATABASE CONFIGURATION ==========
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'stuflow_secret_key_2024')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'  # In-memory database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ========== EMAIL CONFIGURATION ==========
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'noreply@stuflow.com')
app.config['MAIL_DEBUG'] = True

db = SQLAlchemy(app)
mail = Mail(app)

# ========== MODELS ==========
class VerificationCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)

    def is_valid(self):
        return datetime.utcnow() < self.expires_at and not self.used

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='student')
    email_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    tasks = db.relationship('Task', backref='user', lazy=True, cascade='all, delete-orphan')
    events = db.relationship('Event', backref='user', lazy=True, cascade='all, delete-orphan')
    flashcards = db.relationship('Flashcard', backref='user', lazy=True, cascade='all, delete-orphan')
    eco_logs = db.relationship('EcoLog', backref='user', lazy=True, cascade='all, delete-orphan')
    classes = db.relationship('Class', backref='teacher', lazy=True, cascade='all, delete-orphan')
    announcements = db.relationship('Announcement', backref='teacher', lazy=True, cascade='all, delete-orphan')
    resources = db.relationship('ResourceFile', backref='teacher', lazy=True, cascade='all, delete-orphan')
    submissions = db.relationship('Submission', backref='student', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    due_date = db.Column(db.Date, nullable=False)
    priority = db.Column(db.String(20), default='medium')
    status = db.Column(db.String(50), nullable=False, default='ongoing')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.String(10))
    end_time = db.Column(db.String(10))
    location = db.Column(db.String(200))
    type = db.Column(db.String(20), nullable=False, default='general')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Flashcard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    front = db.Column(db.Text, nullable=False)
    back = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100))
    difficulty = db.Column(db.String(20), default='easy')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_reviewed = db.Column(db.DateTime)

class ResourceFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_name = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer)
    file_type = db.Column(db.String(50))
    class_name = db.Column(db.String(100), default='All Classes')
    description = db.Column(db.Text)
    date_uploaded = db.Column(db.DateTime, default=datetime.utcnow)

class EcoLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    waste_count = db.Column(db.Integer, default=0)
    energy_count = db.Column(db.Integer, default=0)
    transport_count = db.Column(db.Integer, default=0)
    water_count = db.Column(db.Integer, default=0)
    recycling_count = db.Column(db.Integer, default=0)
    total_score = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('user_id', 'date', name='_user_date_uc'),)
    
    def calculate_score(self):
        """Calculate total eco score"""
        self.total_score = (
            self.waste_count * 5 +
            self.energy_count * 5 +
            self.transport_count * 10 +
            self.water_count * 3 +
            self.recycling_count * 8
        )
        return self.total_score

class Class(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    subject = db.Column(db.String(100))
    description = db.Column(db.Text)
    estimated_students = db.Column(db.Integer, default=30)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    recipient = db.Column(db.String(100), nullable=False, default='All Students')
    priority = db.Column(db.String(20), default='normal')
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    submitted_file = db.Column(db.String(255))
    file_name = db.Column(db.String(255))
    status = db.Column(db.String(20), default='submitted')
    date_submitted = db.Column(db.DateTime, default=datetime.utcnow)
    grade = db.Column(db.Integer)
    teacher_comment = db.Column(db.Text)
    feedback_date = db.Column(db.DateTime)
    
    task = db.relationship('Task', backref='submissions', lazy=True)

# ========== EMAIL FUNCTIONS ==========
def send_verification_email(email, verification_code):
    """Send verification email with code"""
    try:
        msg = Message(
            'Verify Your StuFlow Account',
            recipients=[email],
            body=f'''
            Welcome to StuFlow!
            
            Your verification code is: {verification_code}
            
            This code will expire in 15 minutes.
            
            If you didn't request this, please ignore this email.
            
            Best regards,
            The StuFlow Team
            ''',
            html=f'''
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #4361ee;">Welcome to StuFlow! 🎓</h2>
                <p>Your verification code is:</p>
                <div style="background: #f8f9fa; padding: 20px; border-radius: 10px; text-align: center; margin: 20px 0;">
                    <h1 style="color: #4361ee; margin: 0;">{verification_code}</h1>
                </div>
                <p>This code will expire in 15 minutes.</p>
                <p>If you didn't request this, please ignore this email.</p>
                <hr>
                <p style="color: #6c757d; font-size: 12px;">
                    Best regards,<br>
                    The StuFlow Team
                </p>
            </div>
            '''
        )
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def send_welcome_email(user):
    """Send welcome email to new user"""
    try:
        msg = Message(
            f'Welcome to StuFlow, {user.name}!',
            recipients=[user.email],
            body=f'''
            Welcome to StuFlow!
            
            Thank you for creating your account. You're now ready to:
            - Manage your tasks and assignments
            - Track your eco-friendly actions
            - Create study flashcards
            - And much more!
            
            Login to get started: {request.host_url}
            
            Best regards,
            The StuFlow Team
            ''',
            html=f'''
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #4361ee;">Welcome to StuFlow, {user.name}! 🎉</h2>
                <p>Thank you for creating your account. You're now ready to:</p>
                <ul>
                    <li>Manage your tasks and assignments</li>
                    <li>Track your eco-friendly actions</li>
                    <li>Create study flashcards</li>
                    <li>And much more!</li>
                </ul>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{request.host_url}" style="background: #4361ee; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
                        Get Started
                    </a>
                </div>
                <p>If you have any questions, feel free to reply to this email.</p>
                <hr>
                <p style="color: #6c757d; font-size: 12px;">
                    Best regards,<br>
                    The StuFlow Team
                </p>
            </div>
            '''
        )
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending welcome email: {e}")
        return False

def send_password_reset_email(email, reset_token):
    """Send password reset email"""
    try:
        reset_link = f"{request.host_url}reset-password?token={reset_token}"
        msg = Message(
            'Reset Your StuFlow Password',
            recipients=[email],
            body=f'''
            You requested a password reset.
            
            Click the link below to reset your password:
            {reset_link}
            
            This link will expire in 1 hour.
            
            If you didn't request this, please ignore this email.
            
            Best regards,
            The StuFlow Team
            ''',
            html=f'''
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #4361ee;">Reset Your Password</h2>
                <p>You requested a password reset. Click the button below to reset your password:</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{reset_link}" style="background: #4361ee; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
                        Reset Password
                    </a>
                </div>
                <p>This link will expire in 1 hour.</p>
                <p>If you didn't request this, please ignore this email.</p>
                <hr>
                <p style="color: #6c757d; font-size: 12px;">
                    Best regards,<br>
                    The StuFlow Team
                </p>
            </div>
            '''
        )
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending reset email: {e}")
        return False

# ========== AUTH DECORATORS ==========
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header:
            if auth_header.startswith('Bearer '):
                token = auth_header.split(" ")[1]
            else:
                token = auth_header

        if not token:
            return jsonify({'success': False, 'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['user_id']).first()
            if not current_user:
                return jsonify({'success': False, 'message': 'Token invalid: User not found'}), 401
            g.current_user = current_user
        except jwt.ExpiredSignatureError:
            return jsonify({'success': False, 'message': 'Token expired'}), 401
        except Exception as e:
            return jsonify({'success': False, 'message': f'Token invalid: {str(e)}'}), 401
        
        return f(*args, **kwargs)
    return decorated

def role_required(roles):
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            role_list = [roles] if isinstance(roles, str) else roles
            if g.current_user.role not in role_list:
                return jsonify({'success': False, 'message': 'Access forbidden: Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated
    return wrapper

# ========== HEALTH CHECK ==========
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'success': True,
        'status': 'healthy',
        'message': 'StuFlow API is running',
        'timestamp': datetime.utcnow().isoformat(),
        'database': 'in-memory SQLite',
        'mail_server': 'configured' if app.config['MAIL_USERNAME'] else 'not configured'
    }), 200

@app.route('/')
def home_page():
    return render_template("index.html")

@app.route('/api')
def home():
    return jsonify({
        "success": True,
        "message": "StuFlow API is running successfully.",
        "version": "2.0.0",
        "database": "in-memory",
        "users_count": User.query.count()
    }), 200

# ========== AUTH ENDPOINTS ==========
@app.route('/api/auth/send-verification', methods=['POST'])
def send_verification():
    """Send verification code to email"""
    if not request.is_json:
        return jsonify({"success": False, "message": "Content-Type must be application/json"}), 415

    data = request.get_json()
    email = data.get('email')
    
    if not email:
        return jsonify({"success": False, "message": "Email is required"}), 400

    # Check if user exists
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    # Generate verification code
    verification_code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
    expires_at = datetime.utcnow() + timedelta(minutes=15)
    
    # Delete old verification codes for this email
    VerificationCode.query.filter_by(email=email).delete()
    
    # Create new verification code
    verification = VerificationCode(
        email=email,
        code=verification_code,
        expires_at=expires_at
    )
    
    try:
        db.session.add(verification)
        db.session.commit()
        
        # Send email
        if send_verification_email(email, verification_code):
            return jsonify({
                "success": True,
                "message": "Verification code sent to your email",
                "email": email
            }), 200
        else:
            return jsonify({
                "success": False,
                "message": "Failed to send verification email"
            }), 500
            
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

@app.route('/api/auth/verify', methods=['POST'])
def verify_code():
    """Verify email with code"""
    if not request.is_json:
        return jsonify({"success": False, "message": "Content-Type must be application/json"}), 415

    data = request.get_json()
    email = data.get('email')
    code = data.get('code')

    if not email or not code:
        return jsonify({"success": False, "message": "Email and code required"}), 400

    # Find verification code
    verification = VerificationCode.query.filter_by(
        email=email, 
        code=code, 
        used=False
    ).first()

    if not verification or not verification.is_valid():
        return jsonify({"success": False, "message": "Invalid or expired code"}), 401

    # Find user
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    # Mark verification as used
    verification.used = True
    user.email_verified = True
    
    # Generate JWT token
    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    try:
        db.session.commit()
        
        # Send welcome email
        send_welcome_email(user)
        
        return jsonify({
            "success": True,
            "token": token,
            "user": {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "role": user.role,
                "email_verified": user.email_verified
            },
            "message": "Email verified successfully!"
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

@app.route('/api/auth/signup', methods=['POST'])
def signup():
    """User registration"""
    if not request.is_json:
        return jsonify({"success": False, "message": "Content-Type must be application/json"}), 415

    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'student')

    if not all([name, email, password]):
        return jsonify({'success': False, 'message': 'Name, email, and password are required.'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'message': 'Account already exists.'}), 409

    if role not in ['student', 'teacher']:
        return jsonify({'success': False, 'message': 'Role must be student or teacher.'}), 400

    new_user = User(name=name, email=email, role=role)
    new_user.set_password(password)

    try:
        db.session.add(new_user)
        db.session.commit()

        # Generate verification code
        verification_code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        expires_at = datetime.utcnow() + timedelta(minutes=15)
        
        verification = VerificationCode(
            email=email,
            code=verification_code,
            expires_at=expires_at
        )
        db.session.add(verification)
        db.session.commit()
        
        # Send verification email
        send_verification_email(email, verification_code)
        
        # Generate JWT token
        token = jwt.encode({
            'user_id': new_user.id,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({
            'success': True,
            'message': 'Account created! Please check your email for verification.', 
            'token': token,
            'user': {
                'id': new_user.id,
                'name': new_user.name,
                'email': new_user.email,
                'role': new_user.role,
                'email_verified': False
            },
            'requires_verification': True
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login"""
    if not request.is_json:
        return jsonify({"success": False, "message": "Content-Type must be application/json"}), 415

    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"success": False, "message": "Email and password required"}), 400

    user = User.query.filter_by(email=email).first()

    if not user or not user.check_password(password):
        return jsonify({"success": False, "message": "Invalid email or password"}), 401

    # Generate JWT token
    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({
        'success': True,
        'token': token,
        'user': {
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'role': user.role,
            'email_verified': user.email_verified
        },
        'message': 'Login successful!'
    }), 200

@app.route('/api/auth/forgot-password', methods=['POST'])
def forgot_password():
    """Request password reset"""
    if not request.is_json:
        return jsonify({"success": False, "message": "Content-Type must be application/json"}), 415

    data = request.get_json()
    email = data.get('email')
    
    if not email:
        return jsonify({"success": False, "message": "Email is required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        # Don't reveal if user exists or not
        return jsonify({
            "success": True,
            "message": "If an account exists with this email, you will receive a reset link."
        }), 200

    # Generate reset token
    reset_token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(hours=1),
        'type': 'password_reset'
    }, app.config['SECRET_KEY'], algorithm="HS256")

    # Send reset email
    if send_password_reset_email(email, reset_token):
        return jsonify({
            "success": True,
            "message": "Password reset link sent to your email."
        }), 200
    else:
        return jsonify({
            "success": False,
            "message": "Failed to send reset email"
        }), 500

@app.route('/api/auth/reset-password', methods=['POST'])
def reset_password():
    """Reset password with token"""
    if not request.is_json:
        return jsonify({"success": False, "message": "Content-Type must be application/json"}), 415

    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')
    
    if not token or not new_password:
        return jsonify({"success": False, "message": "Token and new password are required"}), 400

    try:
        # Decode token
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        
        if payload.get('type') != 'password_reset':
            return jsonify({"success": False, "message": "Invalid token type"}), 401
        
        user_id = payload.get('user_id')
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({"success": False, "message": "User not found"}), 404
        
        # Update password
        user.set_password(new_password)
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": "Password reset successful!"
        }), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({"success": False, "message": "Reset token has expired"}), 401
    except Exception as e:
        return jsonify({"success": False, "message": f"Invalid token: {str(e)}"}), 401

# ========== USER ENDPOINTS ==========
@app.route('/api/user/me', methods=['GET'])
@token_required
def get_current_user():
    return jsonify({
        'success': True,
        'user': {
            'id': g.current_user.id,
            'name': g.current_user.name,
            'email': g.current_user.email,
            'role': g.current_user.role,
            'email_verified': g.current_user.email_verified,
            'created_at': g.current_user.created_at.isoformat()
        }
    }), 200

@app.route('/api/user/profile', methods=['PUT'])
@token_required
def update_profile():
    data = request.get_json()
    
    if 'name' in data:
        g.current_user.name = data['name']
    
    if 'email' in data:
        new_email = data['email']
        if new_email != g.current_user.email:
            # Check if email already exists
            existing_user = User.query.filter_by(email=new_email).first()
            if existing_user and existing_user.id != g.current_user.id:
                return jsonify({'success': False, 'message': 'Email already in use.'}), 409
            g.current_user.email = new_email
            g.current_user.email_verified = False
    
    try:
        db.session.commit()
        return jsonify({
            'success': True,
            'message': 'Profile updated successfully!',
            'user': {
                'id': g.current_user.id,
                'name': g.current_user.name,
                'email': g.current_user.email,
                'email_verified': g.current_user.email_verified
            }
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error updating profile: {str(e)}'}), 500

@app.route('/api/user/change-password', methods=['POST'])
@token_required
def change_password():
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    if not current_password or not new_password:
        return jsonify({'success': False, 'message': 'Current and new password are required.'}), 400
    
    # Verify current password
    if not g.current_user.check_password(current_password):
        return jsonify({'success': False, 'message': 'Current password is incorrect.'}), 401
    
    # Update password
    g.current_user.set_password(new_password)
    
    try:
        db.session.commit()
        return jsonify({'success': True, 'message': 'Password changed successfully!'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error changing password: {str(e)}'}), 500

# ========== ECO LOG ENDPOINTS ==========
@app.route('/api/eco-log/action', methods=['POST'])
@token_required
def log_eco_action():
    """Log an eco-friendly action"""
    if not request.is_json:
        return jsonify({"success": False, "message": "Content-Type must be application/json"}), 415

    data = request.get_json()
    action_type = data.get('action_type')
    
    if not action_type:
        return jsonify({'success': False, 'message': 'Action type is required.'}), 400

    # Validate action type
    valid_actions = ['waste', 'energy', 'transport', 'water', 'recycling']
    if action_type not in valid_actions:
        return jsonify({
            'success': False, 
            'message': f'Invalid action type. Must be one of: {", ".join(valid_actions)}'
        }), 400

    today = datetime.utcnow().date()
    log = EcoLog.query.filter_by(user_id=g.current_user.id, date=today).first()

    if not log:
        log = EcoLog(user_id=g.current_user.id, date=today)
        db.session.add(log)

    # Update the specific action count
    if action_type == 'waste':
        log.waste_count += 1
        points = 5
    elif action_type == 'energy':
        log.energy_count += 1
        points = 5
    elif action_type == 'transport':
        log.transport_count += 1
        points = 10
    elif action_type == 'water':
        log.water_count += 1
        points = 3
    elif action_type == 'recycling':
        log.recycling_count += 1
        points = 8
    
    # Calculate total score
    log.calculate_score()
    
    # Get action name for response
    action_names = {
        'waste': 'Waste Reduction',
        'energy': 'Energy Saving',
        'transport': 'Green Transport',
        'water': 'Water Conservation',
        'recycling': 'Recycling'
    }

    try:
        db.session.commit()
        return jsonify({
            'success': True,
            'message': f'{action_names[action_type]} action logged successfully!',
            'data': {
                'action_type': action_type,
                'action_name': action_names[action_type],
                'points_earned': points,
                'today_stats': {
                    'waste': log.waste_count,
                    'energy': log.energy_count,
                    'transport': log.transport_count,
                    'water': log.water_count,
                    'recycling': log.recycling_count,
                    'total_score': log.total_score
                },
                'date': today.strftime('%Y-%m-%d')
            }
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

@app.route('/api/eco-log/today', methods=['GET'])
@token_required
def get_today_eco_log():
    """Get today's eco log"""
    today = datetime.utcnow().date()
    log = EcoLog.query.filter_by(user_id=g.current_user.id, date=today).first()
    
    if not log:
        # Return empty stats if no log exists for today
        return jsonify({
            'success': True,
            'data': {
                'date': today.strftime('%Y-%m-%d'),
                'waste': 0,
                'energy': 0,
                'transport': 0,
                'water': 0,
                'recycling': 0,
                'total_score': 0,
                'actions_today': 0
            }
        }), 200
    
    total_actions = (
        log.waste_count + 
        log.energy_count + 
        log.transport_count + 
        log.water_count + 
        log.recycling_count
    )
    
    return jsonify({
        'success': True,
        'data': {
            'date': log.date.strftime('%Y-%m-%d'),
            'waste': log.waste_count,
            'energy': log.energy_count,
            'transport': log.transport_count,
            'water': log.water_count,
            'recycling': log.recycling_count,
            'total_score': log.total_score,
            'actions_today': total_actions
        }
    }), 200

@app.route('/api/eco-log/history', methods=['GET'])
@token_required
def get_eco_log_history():
    """Get eco log history"""
    try:
        days = int(request.args.get('days', 30))
    except ValueError:
        days = 30
    
    start_date = datetime.utcnow().date() - timedelta(days=days)
    
    logs = EcoLog.query.filter(
        EcoLog.user_id == g.current_user.id,
        EcoLog.date >= start_date
    ).order_by(EcoLog.date.desc()).all()
    
    # Calculate statistics
    total_actions = 0
    total_score = 0
    daily_average = 0
    
    for log in logs:
        total_actions += (
            log.waste_count + 
            log.energy_count + 
            log.transport_count + 
            log.water_count + 
            log.recycling_count
        )
        total_score += log.total_score
    
    if logs:
        daily_average = total_score / len(logs)
    
    # Prepare chart data
    dates = []
    scores = []
    
    for log in reversed(logs[-14:]):  # Last 14 days for chart
        dates.append(log.date.strftime('%m-%d'))
        scores.append(log.total_score)
    
    return jsonify({
        'success': True,
        'data': {
            'logs': [{
                'date': log.date.strftime('%Y-%m-%d'),
                'waste': log.waste_count,
                'energy': log.energy_count,
                'transport': log.transport_count,
                'water': log.water_count,
                'recycling': log.recycling_count,
                'total_score': log.total_score
            } for log in logs],
            'statistics': {
                'total_days': len(logs),
                'total_actions': total_actions,
                'total_score': total_score,
                'daily_average': round(daily_average, 1),
                'start_date': start_date.strftime('%Y-%m-%d'),
                'end_date': datetime.utcnow().date().strftime('%Y-%m-%d')
            },
            'chart_data': {
                'dates': dates,
                'scores': scores
            }
        }
    }), 200

@app.route('/api/eco-log/leaderboard', methods=['GET'])
@token_required
def get_eco_leaderboard():
    """Get eco score leaderboard"""
    # Get date range (default: last 7 days)
    try:
        days = int(request.args.get('days', 7))
    except ValueError:
        days = 7
    
    start_date = datetime.utcnow().date() - timedelta(days=days)
    
    # Query to get total scores for each user in the date range
    # This is a simplified version - in production you'd want to optimize this query
    all_logs = EcoLog.query.filter(EcoLog.date >= start_date).all()
    
    # Group by user and calculate totals
    user_scores = {}
    for log in all_logs:
        if log.user_id not in user_scores:
            user_scores[log.user_id] = {
                'total_score': 0,
                'user': None
            }
        user_scores[log.user_id]['total_score'] += log.total_score
    
    # Get user details
    for user_id in user_scores.keys():
        user = User.query.get(user_id)
        if user:
            user_scores[user_id]['user'] = {
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'role': user.role
            }
    
    # Convert to list and sort by score
    leaderboard = []
    for user_id, data in user_scores.items():
        if data['user']:  # Only include users that exist
            leaderboard.append({
                'user': data['user'],
                'total_score': data['total_score']
            })
    
    # Sort by score descending
    leaderboard.sort(key=lambda x: x['total_score'], reverse=True)
    
    # Add rank
    for i, entry in enumerate(leaderboard):
        entry['rank'] = i + 1
    
    # Get current user's rank
    current_user_rank = None
    current_user_score = 0
    
    for i, entry in enumerate(leaderboard):
        if entry['user']['id'] == g.current_user.id:
            current_user_rank = i + 1
            current_user_score = entry['total_score']
            break
    
    return jsonify({
        'success': True,
        'data': {
            'leaderboard': leaderboard[:10],  # Top 10
            'current_user': {
                'rank': current_user_rank,
                'score': current_user_score,
                'is_in_top_10': current_user_rank <= 10 if current_user_rank else False
            },
            'time_period': {
                'days': days,
                'start_date': start_date.strftime('%Y-%m-%d'),
                'end_date': datetime.utcnow().date().strftime('%Y-%m-%d')
            }
        }
    }), 200

# ========== TASK ENDPOINTS ==========
@app.route('/api/tasks', methods=['GET'])
@token_required
def get_tasks():
    """Get user's tasks"""
    status_filter = request.args.get('status')
    priority_filter = request.args.get('priority')
    
    query = Task.query.filter_by(user_id=g.current_user.id)
    
    if status_filter:
        query = query.filter_by(status=status_filter)
    
    if priority_filter:
        query = query.filter_by(priority=priority_filter)
    
    tasks = query.order_by(Task.due_date.asc(), Task.priority.desc()).all()
    
    return jsonify({
        'success': True,
        'data': {
            'tasks': [{
                'id': task.id,
                'title': task.title,
                'description': task.description,
                'due_date': task.due_date.strftime('%Y-%m-%d'),
                'priority': task.priority,
                'status': task.status,
                'created_at': task.created_at.strftime('%Y-%m-%d %H:%M'),
                'completed_at': task.completed_at.strftime('%Y-%m-%d %H:%M') if task.completed_at else None
            } for task in tasks],
            'count': len(tasks),
            'filters': {
                'status': status_filter,
                'priority': priority_filter
            }
        }
    }), 200

@app.route('/api/tasks', methods=['POST'])
@token_required
def create_task():
    """Create a new task"""
    if not request.is_json:
        return jsonify({"success": False, "message": "Content-Type must be application/json"}), 415

    data = request.get_json()
    
    if not data.get('title') or not data.get('due_date'):
        return jsonify({'success': False, 'message': 'Title and due date are required.'}), 400

    try:
        new_task = Task(
            user_id=g.current_user.id,
            title=data['title'],
            description=data.get('description', ''),
            due_date=datetime.strptime(data['due_date'], '%Y-%m-%d').date(),
            priority=data.get('priority', 'medium'),
            status='ongoing'
        )
        db.session.add(new_task)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Task created successfully!', 
            'data': {
                'id': new_task.id,
                'title': new_task.title,
                'due_date': new_task.due_date.strftime('%Y-%m-%d')
            }
        }), 201
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid date format. Use YYYY-MM-DD.'}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

@app.route('/api/tasks/<int:task_id>', methods=['GET'])
@token_required
def get_task(task_id):
    """Get a specific task"""
    task = Task.query.filter_by(id=task_id, user_id=g.current_user.id).first()
    
    if not task:
        return jsonify({'success': False, 'message': 'Task not found.'}), 404
    
    return jsonify({
        'success': True,
        'data': {
            'task': {
                'id': task.id,
                'title': task.title,
                'description': task.description,
                'due_date': task.due_date.strftime('%Y-%m-%d'),
                'priority': task.priority,
                'status': task.status,
                'created_at': task.created_at.strftime('%Y-%m-%d %H:%M'),
                'completed_at': task.completed_at.strftime('%Y-%m-%d %H:%M') if task.completed_at else None
            }
        }
    }), 200

@app.route('/api/tasks/<int:task_id>', methods=['PUT'])
@token_required
def update_task(task_id):
    """Update a task"""
    task = Task.query.filter_by(id=task_id, user_id=g.current_user.id).first()
    
    if not task:
        return jsonify({'success': False, 'message': 'Task not found.'}), 404

    data = request.get_json()
    
    if 'title' in data:
        task.title = data['title']
    if 'description' in data:
        task.description = data['description']
    if 'due_date' in data:
        try:
            task.due_date = datetime.strptime(data['due_date'], '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'success': False, 'message': 'Invalid date format. Use YYYY-MM-DD.'}), 400
    if 'priority' in data:
        task.priority = data['priority']
    if 'status' in data:
        task.status = data['status']
        if data['status'] == 'completed' and not task.completed_at:
            task.completed_at = datetime.utcnow()
        elif data['status'] != 'completed':
            task.completed_at = None
    
    try:
        db.session.commit()
        return jsonify({'success': True, 'message': 'Task updated successfully!'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

@app.route('/api/tasks/<int:task_id>/complete', methods=['PUT'])
@token_required
def complete_task(task_id):
    """Mark task as completed"""
    task = Task.query.filter_by(id=task_id, user_id=g.current_user.id).first()
    
    if not task:
        return jsonify({'success': False, 'message': 'Task not found.'}), 404

    task.status = 'completed'
    task.completed_at = datetime.utcnow()
    
    try:
        db.session.commit()
        return jsonify({'success': True, 'message': 'Task marked as completed!'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

@app.route('/api/tasks/<int:task_id>', methods=['DELETE'])
@token_required
def delete_task(task_id):
    """Delete a task"""
    task = Task.query.filter_by(id=task_id, user_id=g.current_user.id).first()
    
    if not task:
        return jsonify({'success': False, 'message': 'Task not found.'}), 404

    try:
        db.session.delete(task)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Task deleted successfully!'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

# ========== FLASHCARD ENDPOINTS ==========
@app.route('/api/flashcards', methods=['GET'])
@token_required
def get_flashcards():
    """Get user's flashcards"""
    category_filter = request.args.get('category')
    difficulty_filter = request.args.get('difficulty')
    
    query = Flashcard.query.filter_by(user_id=g.current_user.id)
    
    if category_filter:
        query = query.filter_by(category=category_filter)
    
    if difficulty_filter:
        query = query.filter_by(difficulty=difficulty_filter)
    
    flashcards = query.order_by(Flashcard.created_at.desc()).all()
    
    # Get unique categories for filtering
    categories = db.session.query(Flashcard.category).filter_by(
        user_id=g.current_user.id
    ).distinct().all()
    
    return jsonify({
        'success': True,
        'data': {
            'flashcards': [{
                'id': card.id,
                'front': card.front,
                'back': card.back,
                'category': card.category,
                'difficulty': card.difficulty,
                'created_at': card.created_at.strftime('%Y-%m-%d %H:%M'),
                'last_reviewed': card.last_reviewed.strftime('%Y-%m-%d %H:%M') if card.last_reviewed else None
            } for card in flashcards],
            'categories': [cat[0] for cat in categories if cat[0]],
            'count': len(flashcards)
        }
    }), 200

@app.route('/api/flashcards', methods=['POST'])
@token_required
def create_flashcard():
    """Create a new flashcard"""
    if not request.is_json:
        return jsonify({"success": False, "message": "Content-Type must be application/json"}), 415

    data = request.get_json()
    if not data.get('front') or not data.get('back'):
        return jsonify({'success': False, 'message': 'Front and back are required.'}), 400

    new_card = Flashcard(
        user_id=g.current_user.id,
        front=data['front'],
        back=data['back'],
        category=data.get('category'),
        difficulty=data.get('difficulty', 'easy')
    )
    
    try:
        db.session.add(new_card)
        db.session.commit()
        return jsonify({
            'success': True,
            'message': 'Flashcard created successfully!', 
            'data': {
                'id': new_card.id,
                'front': new_card.front
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

@app.route('/api/flashcards/<int:card_id>/review', methods=['PUT'])
@token_required
def review_flashcard(card_id):
    """Mark flashcard as reviewed"""
    card = Flashcard.query.filter_by(id=card_id, user_id=g.current_user.id).first()
    
    if not card:
        return jsonify({'success': False, 'message': 'Flashcard not found.'}), 404

    card.last_reviewed = datetime.utcnow()
    
    try:
        db.session.commit()
        return jsonify({'success': True, 'message': 'Flashcard marked as reviewed!'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

# ========== EVENT ENDPOINTS ==========
@app.route('/api/events', methods=['GET'])
@token_required
def get_events():
    """Get user's events"""
    start_date = request.args.get('start')
    end_date = request.args.get('end')
    type_filter = request.args.get('type')
    
    query = Event.query.filter_by(user_id=g.current_user.id)
    
    if start_date:
        try:
            start = datetime.strptime(start_date, '%Y-%m-%d').date()
            query = query.filter(Event.date >= start)
        except ValueError:
            pass
    
    if end_date:
        try:
            end = datetime.strptime(end_date, '%Y-%m-%d').date()
            query = query.filter(Event.date <= end)
        except ValueError:
            pass
    
    if type_filter:
        query = query.filter_by(type=type_filter)
    
    events = query.order_by(Event.date.asc(), Event.start_time.asc()).all()
    
    return jsonify({
        'success': True,
        'data': {
            'events': [{
                'id': event.id,
                'title': event.title,
                'description': event.description,
                'date': event.date.strftime('%Y-%m-%d'),
                'start_time': event.start_time,
                'end_time': event.end_time,
                'location': event.location,
                'type': event.type,
                'created_at': event.created_at.strftime('%Y-%m-%d %H:%M')
            } for event in events],
            'count': len(events)
        }
    }), 200

# ========== CLASS ENDPOINTS (Teacher Only) ==========
@app.route('/api/classes', methods=['GET'])
@token_required
@role_required('teacher')
def get_classes():
    """Get teacher's classes"""
    classes = Class.query.filter_by(teacher_id=g.current_user.id).order_by(Class.created_at.desc()).all()
    
    return jsonify({
        'success': True,
        'data': {
            'classes': [{
                'id': cls.id,
                'name': cls.name,
                'subject': cls.subject,
                'description': cls.description,
                'estimated_students': cls.estimated_students,
                'created_at': cls.created_at.strftime('%Y-%m-%d %H:%M')
            } for cls in classes],
            'count': len(classes)
        }
    }), 200

# ========== ANNOUNCEMENT ENDPOINTS ==========
@app.route('/api/announcements', methods=['GET'])
@token_required
def get_announcements():
    """Get announcements"""
    if g.current_user.role == 'teacher':
        announcements = Announcement.query.filter_by(teacher_id=g.current_user.id)
    else:
        announcements = Announcement.query.filter(
            (Announcement.recipient == 'All Students') | 
            (Announcement.recipient == g.current_user.role.capitalize() + 's')
        )
    
    announcements = announcements.order_by(Announcement.date_posted.desc()).all()
    
    # Get teacher names
    result = []
    for ann in announcements:
        teacher = User.query.get(ann.teacher_id)
        result.append({
            'id': ann.id,
            'title': ann.title,
            'message': ann.message,
            'recipient': ann.recipient,
            'priority': ann.priority,
            'teacher_name': teacher.name if teacher else 'Unknown Teacher',
            'date_posted': ann.date_posted.strftime('%Y-%m-%d %H:%M'),
            'expires_at': ann.expires_at.strftime('%Y-%m-%d %H:%M') if ann.expires_at else None
        })
    
    return jsonify({
        'success': True,
        'data': {
            'announcements': result,
            'count': len(result)
        }
    }), 200

# ========== SUBMISSION ENDPOINTS ==========
@app.route('/api/submissions', methods=['GET'])
@token_required
@role_required('teacher')
def get_submissions():
    """Get all submissions (teacher only)"""
    submissions = Submission.query.all()
    
    result = []
    for sub in submissions:
        task = Task.query.get(sub.task_id)
        student = User.query.get(sub.student_id)
        
        if task and student:
            result.append({
                'id': sub.id,
                'task_id': sub.task_id,
                'task_title': task.title,
                'student_id': sub.student_id,
                'student_name': student.name,
                'submitted_file': sub.submitted_file,
                'file_name': sub.file_name,
                'status': sub.status,
                'date_submitted': sub.date_submitted.strftime('%Y-%m-%d %H:%M'),
                'grade': sub.grade,
                'teacher_comment': sub.teacher_comment,
                'feedback_date': sub.feedback_date.strftime('%Y-%m-%d %H:%M') if sub.feedback_date else None
            })
    
    return jsonify({
        'success': True,
        'data': {
            'submissions': result,
            'count': len(result)
        }
    }), 200

# ========== RESOURCE ENDPOINTS ==========
@app.route('/api/resources', methods=['GET'])
@token_required
def get_resources():
    """Get resources"""
    if g.current_user.role == 'teacher':
        resources = ResourceFile.query.filter_by(teacher_id=g.current_user.id).all()
    else:
        resources = ResourceFile.query.filter(
            (ResourceFile.class_name == 'All Classes') |
            (ResourceFile.class_name == 'Students')
        ).all()
    
    result = []
    for res in resources:
        teacher = User.query.get(res.teacher_id)
        result.append({
            'id': res.id,
            'file_name': res.file_name,
            'file_type': res.file_type,
            'file_size': res.file_size,
            'class_name': res.class_name,
            'description': res.description,
            'teacher_name': teacher.name if teacher else 'Unknown Teacher',
            'date_uploaded': res.date_uploaded.strftime('%Y-%m-%d %H:%M')
        })
    
    return jsonify({
        'success': True,
        'data': {
            'resources': result,
            'count': len(result)
        }
    }), 200

# ========== STATISTICS ENDPOINTS ==========
@app.route('/api/stats/overview', methods=['GET'])
@token_required
def get_stats_overview():
    """Get user statistics overview"""
    # Task statistics
    total_tasks = Task.query.filter_by(user_id=g.current_user.id).count()
    completed_tasks = Task.query.filter_by(user_id=g.current_user.id, status='completed').count()
    pending_tasks = Task.query.filter_by(user_id=g.current_user.id, status='ongoing').count()
    
    # Flashcard statistics
    total_flashcards = Flashcard.query.filter_by(user_id=g.current_user.id).count()
    reviewed_flashcards = Flashcard.query.filter_by(
        user_id=g.current_user.id
    ).filter(Flashcard.last_reviewed.isnot(None)).count()
    
    # Event statistics
    total_events = Event.query.filter_by(user_id=g.current_user.id).count()
    upcoming_events = Event.query.filter(
        Event.user_id == g.current_user.id,
        Event.date >= datetime.utcnow().date()
    ).count()
    
    # Eco log statistics
    today = datetime.utcnow().date()
    today_log = EcoLog.query.filter_by(user_id=g.current_user.id, date=today).first()
    today_score = today_log.total_score if today_log else 0
    
    total_score = db.session.query(db.func.sum(EcoLog.total_score)).filter_by(
        user_id=g.current_user.id
    ).scalar() or 0
    
    # Submission statistics (for students)
    if g.current_user.role == 'student':
        total_submissions = Submission.query.filter_by(student_id=g.current_user.id).count()
        graded_submissions = Submission.query.filter_by(
            student_id=g.current_user.id
        ).filter(Submission.grade.isnot(None)).count()
    else:
        total_submissions = 0
        graded_submissions = 0
    
    return jsonify({
        'success': True,
        'data': {
            'tasks': {
                'total': total_tasks,
                'completed': completed_tasks,
                'pending': pending_tasks,
                'completion_rate': round((completed_tasks / total_tasks * 100) if total_tasks > 0 else 0, 1)
            },
            'flashcards': {
                'total': total_flashcards,
                'reviewed': reviewed_flashcards,
                'review_rate': round((reviewed_flashcards / total_flashcards * 100) if total_flashcards > 0 else 0, 1)
            },
            'events': {
                'total': total_events,
                'upcoming': upcoming_events
            },
            'eco_log': {
                'today_score': today_score,
                'total_score': total_score
            },
            'submissions': {
                'total': total_submissions,
                'graded': graded_submissions,
                'grading_rate': round((graded_submissions / total_submissions * 100) if total_submissions > 0 else 0, 1)
            }
        }
    }), 200

# ========== INITIALIZE DATABASE ==========
def initialize_database():
    """Initialize database with sample data"""
    with app.app_context():
        try:
            db.create_all()
            print("✅ In-memory database tables created successfully")
            
            # Create demo users if none exist
            if not User.query.first():
                # Create demo teacher
                teacher = User(
                    name="Demo Teacher", 
                    email="teacher@stuflow.com", 
                    role="teacher"
                )
                teacher.set_password("password123")
                teacher.email_verified = True
                db.session.add(teacher)
                
                # Create demo student
                student = User(
                    name="Demo Student", 
                    email="student@stuflow.com", 
                    role="student"
                )
                student.set_password("password123")
                student.email_verified = True
                db.session.add(student)
                
                db.session.commit()
                print("✅ Demo users created:")
                print("   Teacher: teacher@stuflow.com / password123")
                print("   Student: student@stuflow.com / password123")
                
                # Create sample tasks for demo student
                today = datetime.utcnow().date()
                
                sample_tasks = [
                    {
                        'user_id': student.id,
                        'title': 'Complete Math Assignment',
                        'description': 'Chapter 5 exercises 1-20',
                        'due_date': today + timedelta(days=2),
                        'priority': 'high',
                        'status': 'ongoing'
                    },
                    {
                        'user_id': student.id,
                        'title': 'Read Science Chapter',
                        'description': 'Read pages 45-78',
                        'due_date': today + timedelta(days=1),
                        'priority': 'medium',
                        'status': 'ongoing'
                    },
                    {
                        'user_id': student.id,
                        'title': 'Submit English Essay',
                        'description': '500 words on climate change',
                        'due_date': today + timedelta(days=3),
                        'priority': 'high',
                        'status': 'completed'
                    }
                ]
                
                for task_data in sample_tasks:
                    task = Task(**task_data)
                    db.session.add(task)
                
                # Create sample flashcards
                sample_flashcards = [
                    {
                        'user_id': student.id,
                        'front': 'What is the capital of France?',
                        'back': 'Paris',
                        'category': 'Geography',
                        'difficulty': 'easy'
                    },
                    {
                        'user_id': student.id,
                        'front': 'What is 2 + 2?',
                        'back': '4',
                        'category': 'Math',
                        'difficulty': 'easy'
                    },
                    {
                        'user_id': student.id,
                        'front': 'What is the chemical symbol for water?',
                        'back': 'H₂O',
                        'category': 'Science',
                        'difficulty': 'medium'
                    }
                ]
                
                for card_data in sample_flashcards:
                    card = Flashcard(**card_data)
                    db.session.add(card)
                
                # Create sample events
                sample_events = [
                    {
                        'user_id': student.id,
                        'title': 'Math Exam',
                        'description': 'Final exam for Algebra',
                        'date': today + timedelta(days=5),
                        'start_time': '10:00',
                        'end_time': '12:00',
                        'type': 'exam'
                    },
                    {
                        'user_id': student.id,
                        'title': 'Science Fair',
                        'description': 'Annual science fair exhibition',
                        'date': today + timedelta(days=7),
                        'start_time': '14:00',
                        'end_time': '17:00',
                        'type': 'event'
                    }
                ]
                
                for event_data in sample_events:
                    event = Event(**event_data)
                    db.session.add(event)
                
                # Create sample eco logs for last 7 days
                for i in range(7):
                    log_date = today - timedelta(days=i)
                    log = EcoLog(
                        user_id=student.id,
                        date=log_date,
                        waste_count=random.randint(0, 3),
                        energy_count=random.randint(0, 5),
                        transport_count=random.randint(0, 2),
                        water_count=random.randint(0, 4),
                        recycling_count=random.randint(0, 3)
                    )
                    log.calculate_score()
                    db.session.add(log)
                
                # Create sample class for teacher
                sample_class = Class(
                    id='class_math101',
                    teacher_id=teacher.id,
                    name='Mathematics 101',
                    subject='Mathematics',
                    description='Introduction to basic mathematics',
                    estimated_students=25
                )
                db.session.add(sample_class)
                
                # Create sample announcement
                sample_announcement = Announcement(
                    teacher_id=teacher.id,
                    title='Welcome to Semester 2',
                    message='Please check the updated syllabus on the portal. All assignments are due by Friday.',
                    recipient='All Students',
                    priority='high'
                )
                db.session.add(sample_announcement)
                
                db.session.commit()
                print("✅ Sample data created successfully")
                
        except Exception as e:
            print(f"❌ Error during initialization: {e}")
            db.session.rollback()

# Initialize database when app starts
initialize_database()

# ========== ERROR HANDLERS ==========
@app.errorhandler(404)
def not_found(error):
    return jsonify({'success': False, 'message': 'Resource not found.'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'success': False, 'message': 'Internal server error.'}), 500

# ========== MAIN ==========
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    print(f"🚀 Starting StuFlow API on port {port}")
    print(f"📊 Database: In-memory SQLite")
    print(f"📧 Email: {'Configured' if app.config['MAIL_USERNAME'] else 'Not configured (check .env)'}")
    print(f"🔗 Health check: http://localhost:{port}/api/health")
    print(f"👤 Demo users: teacher@stuflow.com / student@stuflow.com (password: password123)")
    app.run(host='0.0.0.0', port=port, debug=False)
