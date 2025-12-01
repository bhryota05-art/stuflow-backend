import os
from flask import Flask, request, jsonify, g, render_template
from datetime import datetime, timedelta
import jwt
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
import uuid

load_dotenv()

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# ========== IN-MEMORY DATABASE CONFIGURATION ==========
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'stuflow_secret_key_2024')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'  # In-memory database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ========== MODELS ==========
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='student')

    tasks = db.relationship('Task', backref='user', lazy=True, cascade='all, delete-orphan')
    events = db.relationship('Event', backref='user', lazy=True, cascade='all, delete-orphan')
    flashcards = db.relationship('Flashcard', backref='user', lazy=True, cascade='all, delete-orphan')
    eco_logs = db.relationship('EcoLog', backref='user', lazy=True, cascade='all, delete-orphan')
    classes = db.relationship('Class', backref='teacher', lazy=True, cascade='all, delete-orphan')
    announcements = db.relationship('Announcement', backref='teacher', lazy=True, cascade='all, delete-orphan')
    resources = db.relationship('ResourceFile', backref='teacher', lazy=True, cascade='all, delete-orphan')

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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    date = db.Column(db.Date, nullable=False)
    time = db.Column(db.String(10))
    type = db.Column(db.String(20), nullable=False, default='General')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Flashcard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    front = db.Column(db.Text, nullable=False)
    back = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('user_id', 'date', name='_user_date_uc'),)

class Class(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    subject = db.Column(db.String(100))
    estimated_students = db.Column(db.Integer, default=30)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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

# ========== HEALTH CHECK ==========
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'message': 'StuFlow API is running',
        'timestamp': datetime.utcnow().isoformat(),
        'database': 'in-memory SQLite'
    }), 200

@app.route('/')
def home_page():
    return render_template("index.html")

@app.route('/api')
def home():
    return jsonify({
        "status": "ok",
        "message": "StuFlow API is running successfully.",
        "database": "in-memory",
        "users_count": User.query.count()
    }), 200

# ========== AUTH ENDPOINTS ==========
@app.route('/api/signup', methods=['POST'])
def signup():
    if not request.is_json:
        return jsonify({"message": "Content-Type must be application/json"}), 415

    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'student')

    if not all([name, email, password]):
        return jsonify({'message': 'Name, email, and password are required.'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Account already exists.'}), 409

    if role not in ['student', 'teacher']:
        return jsonify({'message': 'Role must be student or teacher.'}), 400

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
            'message': 'Account created successfully!', 
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

@app.route('/api/login', methods=['POST'])
def login():
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

# ========== USER ENDPOINTS ==========
@app.route('/api/user/me', methods=['GET'])
@token_required
def get_current_user():
    return jsonify({
        'id': g.current_user.id,
        'name': g.current_user.name,
        'email': g.current_user.email,
        'role': g.current_user.role
    }), 200

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
    tasks = Task.query.filter_by(user_id=g.current_user.id).order_by(Task.due_date.asc()).all()
    output = []
    for task in tasks:
        output.append({
            'id': task.id,
            'title': task.title,
            'description': task.description,
            'due': task.due_date.strftime('%Y-%m-%d'),
            'status': task.status,
            'created_at': task.created_at.strftime('%Y-%m-%d %H:%M')
        })
    return jsonify(output), 200

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
            status=data.get('status', 'Ongoing')
        )
        db.session.add(new_task)
        db.session.commit()
        return jsonify({
            'message': 'Task created successfully!', 
            'id': new_task.id,
            'title': new_task.title,
            'due': new_task.due_date.strftime('%Y-%m-%d')
        }), 201
    except ValueError:
        return jsonify({'message': 'Invalid date format. Use YYYY-MM-DD.'}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/tasks/<int:task_id>', methods=['PUT'])
@token_required
def update_task(task_id):
    task = Task.query.filter_by(id=task_id, user_id=g.current_user.id).first()
    
    if not task:
        return jsonify({'message': 'Task not found.'}), 404

    data = request.get_json()
    
    if 'title' in data:
        task.title = data['title']
    if 'description' in data:
        task.description = data['description']
    if 'due' in data:
        try:
            task.due_date = datetime.strptime(data['due'], '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'message': 'Invalid date format. Use YYYY-MM-DD.'}), 400
    if 'status' in data:
        task.status = data['status']
    
    try:
        db.session.commit()
        return jsonify({'message': 'Task updated successfully!'}), 200
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
    try:
        db.session.commit()
        return jsonify({'message': 'Task marked as completed!'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/tasks/<int:task_id>', methods=['DELETE'])
@token_required
def delete_task(task_id):
    task = Task.query.filter_by(id=task_id, user_id=g.current_user.id).first()
    
    if not task:
        return jsonify({'message': 'Task not found.'}), 404

    try:
        db.session.delete(task)
        db.session.commit()
        return jsonify({'message': 'Task deleted successfully!'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

# ========== FLASHCARD ENDPOINTS ==========
@app.route('/api/flashcards', methods=['GET'])
@token_required
def get_flashcards():
    flashcards = Flashcard.query.filter_by(user_id=g.current_user.id).order_by(Flashcard.created_at.desc()).all()
    output = [{
        'id': c.id, 
        'front': c.front, 
        'back': c.back,
        'created_at': c.created_at.strftime('%Y-%m-%d %H:%M')
    } for c in flashcards]
    return jsonify(output), 200

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
    try:
        db.session.add(new_card)
        db.session.commit()
        return jsonify({
            'message': 'Flashcard created successfully!', 
            'id': new_card.id,
            'front': new_card.front
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/flashcards/<int:card_id>', methods=['DELETE'])
@token_required
def delete_flashcard(card_id):
    card = Flashcard.query.filter_by(id=card_id, user_id=g.current_user.id).first()
    
    if not card:
        return jsonify({'message': 'Flashcard not found.'}), 404

    try:
        db.session.delete(card)
        db.session.commit()
        return jsonify({'message': 'Flashcard deleted successfully!'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

# ========== EVENT ENDPOINTS ==========
@app.route('/api/events', methods=['GET'])
@token_required
def get_events():
    events = Event.query.filter_by(user_id=g.current_user.id).order_by(Event.date.asc()).all()
    output = [{
        'id': e.id, 
        'title': e.title, 
        'description': e.description,
        'date': e.date.strftime('%Y-%m-%d'),
        'time': e.time,
        'type': e.type,
        'created_at': e.created_at.strftime('%Y-%m-%d %H:%M')
    } for e in events]
    return jsonify(output), 200

@app.route('/api/events', methods=['POST'])
@token_required
def create_event():
    data = request.get_json()
    if not data.get('title') or not data.get('date'):
        return jsonify({'message': 'Title and date are required.'}), 400

    try:
        new_event = Event(
            user_id=g.current_user.id,
            title=data['title'],
            description=data.get('description', ''),
            date=datetime.strptime(data['date'], '%Y-%m-%d').date(),
            time=data.get('time'),
            type=data.get('type', 'General')
        )
        db.session.add(new_event)
        db.session.commit()
        return jsonify({
            'message': 'Event created successfully!', 
            'id': new_event.id,
            'title': new_event.title
        }), 201
    except ValueError:
        return jsonify({'message': 'Invalid date format. Use YYYY-MM-DD.'}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/events/<int:event_id>', methods=['DELETE'])
@token_required
def delete_event(event_id):
    event = Event.query.filter_by(id=event_id, user_id=g.current_user.id).first()
    
    if not event:
        return jsonify({'message': 'Event not found.'}), 404

    try:
        db.session.delete(event)
        db.session.commit()
        return jsonify({'message': 'Event deleted successfully!'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

# ========== ECO LOG ENDPOINTS ==========
@app.route('/api/eco-log/action/<string:action_type>', methods=['POST'])
@token_required
def log_eco_action(action_type):
    if action_type not in ['waste', 'energy', 'transport']:
        return jsonify({'message': 'Invalid action type. Must be waste, energy, or transport.'}), 400

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

    try:
        db.session.commit()
        return jsonify({
            'message': f'{action_type} action logged successfully!',
            'waste': log.waste_count,
            'energy': log.energy_count,
            'transport': log.transport_count,
            'score': log.score,
            'date': today.strftime('%Y-%m-%d')
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/eco-log/daily', methods=['GET'])
@token_required
def get_eco_log():
    today = datetime.utcnow().date()
    log = EcoLog.query.filter_by(user_id=g.current_user.id, date=today).first()
    
    if not log:
        return jsonify({
            'waste': 0, 
            'energy': 0, 
            'transport': 0, 
            'score': 0,
            'date': today.strftime('%Y-%m-%d')
        }), 200
    
    return jsonify({
        'waste': log.waste_count,
        'energy': log.energy_count,
        'transport': log.transport_count,
        'score': log.score,
        'date': log.date.strftime('%Y-%m-%d')
    }), 200

@app.route('/api/eco-log/history', methods=['GET'])
@token_required
def get_eco_log_history():
    logs = EcoLog.query.filter_by(user_id=g.current_user.id).order_by(EcoLog.date.desc()).limit(30).all()
    output = [{
        'date': log.date.strftime('%Y-%m-%d'),
        'waste': log.waste_count,
        'energy': log.energy_count,
        'transport': log.transport_count,
        'score': log.score
    } for log in logs]
    return jsonify(output), 200

# ========== CLASS ENDPOINTS (Teacher Only) ==========
@app.route('/api/classes', methods=['GET'])
@token_required
@role_required('teacher')
def get_classes():
    classes = Class.query.filter_by(teacher_id=g.current_user.id).order_by(Class.created_at.desc()).all()
    output = [{
        'id': c.id, 
        'name': c.name,
        'subject': c.subject,
        'estimated_students': c.estimated_students,
        'created_at': c.created_at.strftime('%Y-%m-%d %H:%M')
    } for c in classes]
    return jsonify(output), 200

@app.route('/api/classes', methods=['POST'])
@token_required
@role_required('teacher')
def create_class():
    data = request.get_json()
    if not data.get('name'):
        return jsonify({'message': 'Class name is required.'}), 400
        
    class_id = f"class_{uuid.uuid4().hex[:8]}"
    new_class = Class(
        id=class_id,
        teacher_id=g.current_user.id,
        name=data['name'],
        subject=data.get('subject'),
        estimated_students=data.get('estimated_students', 30)
    )
    
    try:
        db.session.add(new_class)
        db.session.commit()
        return jsonify({
            'message': 'Class created successfully!', 
            'id': new_class.id,
            'name': new_class.name
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/classes/<string:class_id>', methods=['DELETE'])
@token_required
@role_required('teacher')
def delete_class(class_id):
    class_obj = Class.query.filter_by(id=class_id, teacher_id=g.current_user.id).first()
    
    if not class_obj:
        return jsonify({'message': 'Class not found.'}), 404

    try:
        db.session.delete(class_obj)
        db.session.commit()
        return jsonify({'message': 'Class deleted successfully!'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

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
        recipient=recipient
    )
    
    try:
        db.session.add(new_announcement)
        db.session.commit()
        return jsonify({
            'message': 'Announcement created successfully!', 
            'id': new_announcement.id,
            'title': title
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/announcements', methods=['GET'])
@token_required
def get_announcements():
    if g.current_user.role == 'teacher':
        announcements = Announcement.query.filter_by(teacher_id=g.current_user.id).order_by(Announcement.date_posted.desc()).all()
    else:
        announcements = Announcement.query.filter_by(recipient='All Students').order_by(Announcement.date_posted.desc()).all()
    
    output = [{
        'id': a.id,
        'title': a.title,
        'message': a.message,
        'recipient': a.recipient,
        'teacher_name': a.teacher.name,
        'date': a.date_posted.strftime('%Y-%m-%d %H:%M')
    } for a in announcements]
    return jsonify(output), 200

@app.route('/api/announcements/<int:announcement_id>', methods=['DELETE'])
@token_required
@role_required('teacher')
def delete_announcement(announcement_id):
    announcement = Announcement.query.filter_by(id=announcement_id, teacher_id=g.current_user.id).first()
    
    if not announcement:
        return jsonify({'message': 'Announcement not found.'}), 404

    try:
        db.session.delete(announcement)
        db.session.commit()
        return jsonify({'message': 'Announcement deleted successfully!'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

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
            'date_uploaded': res.date_uploaded.strftime('%Y-%m-%d %H:%M')
        })
    return jsonify(output), 200

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
                db.session.add(teacher)
                
                # Create demo student
                student = User(
                    name="Demo Student", 
                    email="student@stuflow.com", 
                    role="student"
                )
                student.set_password("password123")
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
                        'status': 'Ongoing'
                    },
                    {
                        'user_id': student.id,
                        'title': 'Read Science Chapter',
                        'description': 'Read pages 45-78',
                        'due_date': today + timedelta(days=1),
                        'status': 'Ongoing'
                    },
                    {
                        'user_id': student.id,
                        'title': 'Submit English Essay',
                        'description': '500 words on climate change',
                        'due_date': today + timedelta(days=3),
                        'status': 'Completed'
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
                        'back': 'Paris'
                    },
                    {
                        'user_id': student.id,
                        'front': 'What is 2 + 2?',
                        'back': '4'
                    },
                    {
                        'user_id': student.id,
                        'front': 'What is the chemical symbol for water?',
                        'back': 'H₂O'
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
                        'type': 'Exam'
                    },
                    {
                        'user_id': student.id,
                        'title': 'Science Fair',
                        'description': 'Annual science fair exhibition',
                        'date': today + timedelta(days=7),
                        'type': 'Event'
                    }
                ]
                
                for event_data in sample_events:
                    event = Event(**event_data)
                    db.session.add(event)
                
                # Create sample class for teacher
                sample_class = Class(
                    id='class_math101',
                    teacher_id=teacher.id,
                    name='Mathematics 101',
                    subject='Mathematics',
                    estimated_students=25
                )
                db.session.add(sample_class)
                
                # Create sample announcement
                sample_announcement = Announcement(
                    teacher_id=teacher.id,
                    title='Welcome to Semester 2',
                    message='Please check the updated syllabus on the portal.',
                    recipient='All Students'
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
    return jsonify({'message': 'Resource not found.'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'message': 'Internal server error.'}), 500

# ========== MAIN ==========
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    print(f"🚀 Starting StuFlow API on port {port}")
    print(f"📊 Database: In-memory SQLite")
    print(f"🔗 Health check: http://localhost:{port}/api/health")
    print(f"👤 Demo users available - see above")
    app.run(host='0.0.0.0', port=port, debug=False)
