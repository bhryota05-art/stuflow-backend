import os
from flask import Flask, request, jsonify, g, render_template
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
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')

# Use SQLite file database (will create stuflow.db file)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "stuflow.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ========== EMAIL CONFIGURATION ==========
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'noreply@stuflow.com')

db = SQLAlchemy(app)
mail = Mail(app)

# ========== HEALTH CHECK ==========
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'message': 'StuFlow API is running',
        'timestamp': datetime.utcnow().isoformat()
    }), 200

@app.route('/')
def home_page():
    return render_template("index.html")

@app.route('/api')
def home():
    return jsonify({
        "status": "ok",
        "message": "StuFlow API is running successfully."
    }), 200

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

    tasks = db.relationship('Task', backref='user', lazy=True)
    events = db.relationship('Event', backref='user', lazy=True)
    flashcards = db.relationship('Flashcard', backref='user', lazy=True)
    eco_logs = db.relationship('EcoLog', backref='user', lazy=True)
    classes = db.relationship('Class', backref='teacher', lazy=True)
    announcements = db.relationship('Announcement', backref='teacher', lazy=True)
    resources = db.relationship('ResourceFile', backref='teacher', foreign_keys='ResourceFile.teacher_id', lazy=True)

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
    status = db.Column(db.String(50), nullable=False, default='Ongoing')

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    date = db.Column(db.Date, nullable=False)
    type = db.Column(db.String(20), nullable=False)

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    submitted_file = db.Column(db.String(255))
    status = db.Column(db.String(20), default='Submitted')
    date_submitted = db.Column(db.DateTime, default=datetime.utcnow)
    grade = db.Column(db.Integer)
    teacher_comment = db.Column(db.Text)
    
    task = db.relationship('Task', backref='submissions', lazy=True)
    student = db.relationship('User', backref='submissions', foreign_keys=[student_id], lazy=True)

class Flashcard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    front = db.Column(db.Text, nullable=False)
    back = db.Column(db.Text, nullable=False)

class ResourceFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_name = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    class_name = db.Column(db.String(100), default='All Classes')
    date_uploaded = db.Column(db.DateTime, default=datetime.utcnow)

class EcoLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    waste_count = db.Column(db.Integer, default=0)
    energy_count = db.Column(db.Integer, default=0)
    transport_count = db.Column(db.Integer, default=0)
    score = db.Column(db.Integer, default=0)

    __table_args__ = (db.UniqueConstraint('user_id', 'date', name='_user_date_uc'),)

class Class(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    estimated_students = db.Column(db.Integer, default=0)

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    recipient = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)

# ========== AUTH DECORATORS ==========
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(" ")[1]
            else:
                token = auth_header

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['user_id']).first()
            if not current_user:
                return jsonify({'message': 'Token invalid: User not found'}), 401
            g.current_user = current_user
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expired'}), 401
        except Exception as e:
            return jsonify({'message': f'Token invalid: {str(e)}'}), 401
        
        return f(*args, **kwargs)
    return decorated

def role_required(roles):
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            role_list = [roles] if isinstance(roles, str) else roles
            if g.current_user.role not in role_list:
                return jsonify({'message': 'Access forbidden: Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated
    return wrapper

# ========== AUTH ENDPOINTS ==========
@app.route('/api/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return jsonify({
            "status": "ok",
            "message": "StuFlow Signup Endpoint. Send POST with name, email, password, role."
        }), 200

    if not request.is_json:
        return jsonify({"message": "Content-Type must be application/json"}), 415

    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'student')

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Account already exists.'}), 409

    new_user = User(name=name, email=email, role=role)
    new_user.set_password(password)

    try:
        db.session.add(new_user)
        db.session.commit()

        token = jwt.encode({
            'user_id': new_user.id,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({
            'message': 'Account created!', 
            'token': token,
            'user': {
                'id': new_user.id,
                'name': new_user.name,
                'email': new_user.email,
                'role': new_user.role
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return jsonify({
            "status": "ok",
            "message": "StuFlow Login Endpoint. Send POST with email & password."
        }), 200

    if not request.is_json:
        return jsonify({"message": "Content-Type must be application/json"}), 415

    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"message": "Email and password required"}), 400

    user = User.query.filter_by(email=email).first()

    if not user or not user.check_password(password):
        return jsonify({"message": "Invalid email or password"}), 401

    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({
        'token': token,
        'user': {
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'role': user.role
        },
        'message': 'Login successful!'
    }), 200

@app.route('/api/verify', methods=['GET', 'POST'])
def verify_code():
    if request.method == 'GET':
        return jsonify({
            "status": "ok",
            "message": "Verification endpoint (for email verification)"
        }), 200

    if not request.is_json:
        return jsonify({"message": "Content-Type must be application/json"}), 415

    data = request.get_json()
    email = data.get('email')
    code = data.get('code')

    if not email or not code:
        return jsonify({"message": "Email and code required"}), 400

    verification = VerificationCode.query.filter_by(email=email, code=code, used=False).first()

    if not verification or not verification.is_valid():
        return jsonify({"message": "Invalid or expired code"}), 401

    verification.used = True
    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({"message": "User not found"}), 404

    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    db.session.commit()

    return jsonify({
        "token": token,
        "role": user.role,
        "name": user.name,
        "email": user.email,
        "message": "Verification successful!"
    }), 200

# ========== USER ENDPOINTS ==========
@app.route('/api/user/me', methods=['GET'])
@token_required
def get_current_user():
    return jsonify({
        'id': g.current_user.id,
        'name': g.current_user.name,
        'email': g.current_user.email,
        'role': g.current_user.role
    })

@app.route('/api/user/profile', methods=['PUT'])
@token_required
def update_profile():
    data = request.get_json()
    new_name = data.get('name')
    
    if not new_name:
        return jsonify({'message': 'Name is required.'}), 400

    g.current_user.name = new_name
    try:
        db.session.commit()
        return jsonify({'message': 'Profile updated successfully!', 'name': new_name}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error updating profile: {str(e)}'}), 500

# ========== TASK ENDPOINTS ==========
@app.route('/api/tasks', methods=['GET'])
@token_required
def get_tasks():
    tasks = Task.query.filter_by(user_id=g.current_user.id).all()
    output = []
    for task in tasks:
        output.append({
            'id': task.id,
            'title': task.title,
            'description': task.description,
            'due': task.due_date.strftime('%Y-%m-%d'),
            'status': task.status
        })
    return jsonify(output)

@app.route('/api/tasks', methods=['POST'])
@token_required
def create_task():
    data = request.get_json()
    
    if not data.get('title') or not data.get('due'):
        return jsonify({'message': 'Title and due date are required.'}), 400

    try:
        new_task = Task(
            user_id=g.current_user.id,
            title=data['title'],
            description=data.get('description', ''),
            due_date=datetime.strptime(data['due'], '%Y-%m-%d').date(),
            status='Ongoing'
        )
        db.session.add(new_task)
        db.session.commit()
        return jsonify({
            'message': 'Task created!', 
            'id': new_task.id,
            'title': new_task.title
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/tasks/<int:task_id>/complete', methods=['PUT'])
@token_required
def complete_task(task_id):
    task = Task.query.filter_by(id=task_id, user_id=g.current_user.id).first()
    
    if not task:
        return jsonify({'message': 'Task not found.'}), 404

    task.status = 'Completed'
    db.session.commit()
    return jsonify({'message': 'Task marked as completed!'}), 200

# ========== SUBMISSION ENDPOINTS ==========
@app.route('/api/submissions', methods=['GET'])
@token_required
@role_required('teacher')
def get_submissions():
    submissions = Submission.query.all()
    output = []
    for sub in submissions:
        task = Task.query.filter_by(id=sub.task_id).first()
        student = User.query.filter_by(id=sub.student_id).first()
        if task and student:
            output.append({
                'id': sub.id,
                'task_id': sub.task_id,
                'student_name': student.name,
                'assignment_title': task.title,
                'submitted_file': sub.submitted_file,
                'status': sub.status,
                'grade': sub.grade,
                'teacher_comment': sub.teacher_comment
            })
    return jsonify(output)

# ========== FLASHCARD ENDPOINTS ==========
@app.route('/api/flashcards', methods=['GET'])
@token_required
def get_flashcards():
    flashcards = Flashcard.query.filter_by(user_id=g.current_user.id).all()
    output = [{'id': c.id, 'front': c.front, 'back': c.back} for c in flashcards]
    return jsonify(output)

@app.route('/api/flashcards', methods=['POST'])
@token_required
def create_flashcard():
    data = request.get_json()
    if not data.get('front') or not data.get('back'):
        return jsonify({'message': 'Front and back are required.'}), 400

    new_card = Flashcard(
        user_id=g.current_user.id,
        front=data['front'],
        back=data['back']
    )
    db.session.add(new_card)
    db.session.commit()
    return jsonify({'message': 'Flashcard created!', 'id': new_card.id}), 201

# ========== EVENT ENDPOINTS ==========
@app.route('/api/events', methods=['GET'])
@token_required
def get_events():
    events = Event.query.filter_by(user_id=g.current_user.id).all()
    output = [{'id': e.id, 'title': e.title, 'date': e.date.strftime('%Y-%m-%d'), 'type': e.type} for e in events]
    return jsonify(output)

@app.route('/api/events', methods=['POST'])
@token_required
def create_event():
    data = request.get_json()
    if not data.get('title') or not data.get('date') or not data.get('type'):
        return jsonify({'message': 'Title, date, and type are required.'}), 400

    new_event = Event(
        user_id=g.current_user.id,
        title=data['title'],
        date=datetime.strptime(data['date'], '%Y-%m-%d').date(),
        type=data['type']
    )
    db.session.add(new_event)
    db.session.commit()
    return jsonify({'message': 'Event created!', 'id': new_event.id}), 201

# ========== RESOURCE ENDPOINTS ==========
@app.route('/api/resources', methods=['GET'])
@token_required
def get_resources():
    if g.current_user.role == 'teacher':
        resources = ResourceFile.query.filter_by(teacher_id=g.current_user.id).all()
    else:
        resources = ResourceFile.query.filter_by(class_name='All Classes').all()
    
    output = []
    for res in resources:
        teacher = User.query.get(res.teacher_id)
        output.append({
            'id': res.id,
            'file_name': res.file_name,
            'class_name': res.class_name,
            'teacher_name': teacher.name if teacher else 'Unknown Teacher',
            'date_uploaded': res.date_uploaded.strftime('%Y-%m-%d')
        })
    return jsonify(output)

# ========== ECO LOG ENDPOINTS ==========
@app.route('/api/eco-log/action/<string:action_type>', methods=['POST'])
@token_required
def log_eco_action(action_type):
    if action_type not in ['waste', 'energy', 'transport']:
        return jsonify({'message': 'Invalid action type.'}), 400

    today = datetime.utcnow().date()
    log = EcoLog.query.filter_by(user_id=g.current_user.id, date=today).first()

    if not log:
        log = EcoLog(user_id=g.current_user.id, date=today)
        db.session.add(log)

    if action_type == 'waste':
        log.waste_count += 1
        log.score += 5
    elif action_type == 'energy':
        log.energy_count += 1
        log.score += 5
    elif action_type == 'transport':
        log.transport_count += 1
        log.score += 10

    db.session.commit()
    return jsonify({
        'waste': log.waste_count,
        'energy': log.energy_count,
        'transport': log.transport_count,
        'score': log.score
    }), 200

@app.route('/api/eco-log/daily', methods=['GET'])
@token_required
def get_eco_log():
    today = datetime.utcnow().date()
    log = EcoLog.query.filter_by(user_id=g.current_user.id, date=today).first()
    
    if not log:
        return jsonify({'waste': 0, 'energy': 0, 'transport': 0, 'score': 0}), 200
    
    return jsonify({
        'waste': log.waste_count,
        'energy': log.energy_count,
        'transport': log.transport_count,
        'score': log.score
    }), 200

# ========== CLASS ENDPOINTS ==========
@app.route('/api/classes', methods=['GET'])
@token_required
@role_required('teacher')
def get_classes():
    classes = Class.query.filter_by(teacher_id=g.current_user.id).all()
    output = [{'id': c.id, 'name': c.name, 'estimated_students': c.estimated_students} for c in classes]
    return jsonify(output)

@app.route('/api/classes', methods=['POST'])
@token_required
@role_required('teacher')
def create_class():
    data = request.get_json()
    if not data.get('name'):
        return jsonify({'message': 'Class name is required.'}), 400
        
    class_id = f"class-{uuid.uuid4().hex[:8]}"
    new_class = Class(
        id=class_id,
        teacher_id=g.current_user.id,
        name=data['name'],
        estimated_students=data.get('size', 30)
    )
    db.session.add(new_class)
    db.session.commit()
    return jsonify({'message': 'Class created!', 'id': new_class.id}), 201

# ========== ANNOUNCEMENTS ENDPOINTS ==========
@app.route('/api/announcements', methods=['POST'])
@token_required
@role_required('teacher')
def create_announcement():
    data = request.get_json()
    title = data.get('title')
    message = data.get('message')
    recipient = data.get('recipient')
    
    if not title or not message or not recipient:
        return jsonify({'message': 'Title, message, and recipient are required.'}), 400

    new_announcement = Announcement(
        teacher_id=g.current_user.id,
        title=title,
        message=message,
        recipient=recipient,
        date_posted=datetime.utcnow()
    )
    db.session.add(new_announcement)
    db.session.commit()
    return jsonify({'message': f'Announcement "{title}" posted successfully to {recipient}!'}), 201

@app.route('/api/announcements', methods=['GET'])
@token_required
def get_announcements():
    if g.current_user.role == 'student':
        announcements = Announcement.query.all()
    else:
        announcements = Announcement.query.filter_by(teacher_id=g.current_user.id).all()
    
    output = [{
        'id': a.id,
        'title': a.title,
        'message': a.message,
        'recipient': a.recipient,
        'date': a.date_posted.strftime('%Y-%m-%d')
    } for a in announcements]
    return jsonify(output)

# ========== INITIALIZE DATABASE ==========
@app.before_first_request
def initialize():
    try:
        db.create_all()
        print("Database tables created successfully")
        
        # Create test users if none exist
        if not User.query.first():
            # Create test teacher
            teacher = User(name="Demo Teacher", email="teacher@stuflow.com", role="teacher")
            teacher.set_password("password123")
            db.session.add(teacher)
            
            # Create test student
            student = User(name="Demo Student", email="student@stuflow.com", role="student")
            student.set_password("password123")
            db.session.add(student)
            
            db.session.commit()
            print("Test users created: teacher@stuflow.com / student@stuflow.com (password: password123)")
    except Exception as e:
        print(f"Error during initialization: {e}")

# ========== MAIN ==========
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
