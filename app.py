import os
from datetime import datetime, timedelta
import jwt
import random
from flask import Flask, request, jsonify, g
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

# --- CONFIGURATION ---
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')

app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"mysql+mysqlconnector://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@"
    f"{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email Configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'noreply@stuflow.com')

db = SQLAlchemy(app)
mail = Mail(app)

# --- HOMEPAGE ROUTE ---
@app.route('/')
def home():
    return jsonify({
        "status": "ok",
        "message": "StuFlow API is running successfully."
    }), 200

# --- MODELS ---
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

# --- AUTH DECORATORS ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]

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
        except Exception:
            return jsonify({'message': 'Token invalid'}), 401
        
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

# --- FIXED SIGNUP ENDPOINT ---
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

        return jsonify({'message': 'Account created!', 'token': token}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {e}'}), 500

# --- FIXED LOGIN ENDPOINT ---
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

    code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
    expires_at = datetime.utcnow() + timedelta(minutes=10)

    VerificationCode.query.filter_by(email=email).update({'used': True})

    verification = VerificationCode(
        email=email,
        code=code,
        expires_at=expires_at
    )
    db.session.add(verification)
    db.session.commit()

    try:
        msg = Message(
            subject='StuFlow Verification Code',
            recipients=[email],
            body=f"""
Hello {user.name},

Your verification code is: {code}
(Expires in 10 minutes)

StuFlow Team
"""
        )
        mail.send(msg)
    except Exception as e:
        print(f"Email error: {e}")
        return jsonify({"message": "Email failed"}), 500

    return jsonify({
        "message": "Verification code sent.",
        "requires_verification": True
    }), 200

# --- FIXED VERIFY ENDPOINT ---
@app.route('/api/verify', methods=['GET', 'POST'])
def verify_code():
    if request.method == 'GET':
        return jsonify({
            "status": "ok",
            "message": "Send POST with email & verification code."
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

    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    db.session.commit()

    return jsonify({
        "token": token,
        "role": user.role,
        "name": user.name,
        "message": "Verification successful!"
    }), 200

# --- FIXED RESEND ENDPOINT ---
@app.route('/api/verify/resend', methods=['GET', 'POST'])
def resend_verification():
    if request.method == 'GET':
        return jsonify({
            "status": "ok",
            "message": "Send POST with email to resend verification code."
        }), 200

    if not request.is_json:
        return jsonify({"message": "Content-Type must be application/json"}), 415

    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"message": "Email is required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "User not found"}), 404

    code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
    expires_at = datetime.utcnow() + timedelta(minutes=10)

    VerificationCode.query.filter_by(email=email).update({'used': True})

    verification = VerificationCode(
        email=email,
        code=code,
        expires_at=expires_at
    )
    db.session.add(verification)
    db.session.commit()

    try:
        msg = Message(
            subject='New StuFlow Verification Code',
            recipients=[email],
            body=f"""
Hello {user.name},

Your NEW verification code is: {code}
(Expires in 10 minutes)

StuFlow Team
"""
        )
        mail.send(msg)
    except Exception:
        return jsonify({"message": "Email sending failed"}), 500

    return jsonify({"message": "New verification code sent"}), 200

# --- ALL OTHER ENDPOINTS REMAIN UNCHANGED ---
# (Your original task, event, submission, flashcard, resources, eco-log, class, announcements routes remain the same)

# --- DB INIT COMMAND -
# --- USER ENDPOINTS --

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
    except:
        db.session.rollback()
        return jsonify({'message': 'Error updating profile.'}), 500

@app.route('/api/user/password', methods=['PUT'])
@token_required
def update_password():
    data = request.get_json()
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    
    if not old_password or not new_password:
        return jsonify({'message': 'Old and new passwords are required.'}), 400
        
    if len(new_password) < 6:
        return jsonify({'message': 'New password must be at least 6 characters long.'}), 400

    if not g.current_user.check_password(old_password):
        return jsonify({'message': 'Invalid current password.'}), 401
    
    g.current_user.set_password(new_password)
    
    try:
        db.session.commit()
        return jsonify({'message': 'Password updated successfully.'}), 200
    except Exception:
        db.session.rollback()
        return jsonify({'message': 'Error updating password.'}), 500

# --- TASK ENDPOINTS ---

@app.route('/api/tasks', methods=['GET'])
@token_required
def get_tasks():
    output = []
    if g.current_user.role == 'teacher':
         tasks = Task.query.filter_by(user_id=g.current_user.id, status='Assignment').all()
         for task in tasks:
             output.append({
                 'id': task.id,
                 'title': task.title,
                 'description': task.description,
                 'due': task.due_date.strftime('%Y-%m-%d'),
                 'status': task.status
             })
    else:
         tasks_and_comments = db.session.query(Task, Submission.teacher_comment)\
             .outerjoin(Submission, Submission.task_id == Task.id)\
             .filter(Task.user_id==g.current_user.id).all()
         
         for task, teacher_comment in tasks_and_comments:
             output.append({
                 'id': task.id,
                 'title': task.title,
                 'description': task.description,
                 'due': task.due_date.strftime('%Y-%m-%d'),
                 'status': task.status,
                 'teacher_comment': teacher_comment if teacher_comment else None
             })
             
    return jsonify(output)

@app.route('/api/tasks', methods=['POST'])
@token_required
def create_task():
    data = request.get_json()
    
    if not data.get('title') or not data.get('due'):
        return jsonify({'message': 'Title and due date are required.'}), 400

    if g.current_user.role != 'teacher':
        return jsonify({'message': 'Access forbidden: Only teachers can create assignments.'}), 403

    teacher_task = Task(
        user_id=g.current_user.id,
        title=data['title'],
        description=data.get('description', 'No description provided.'),
        due_date=datetime.strptime(data['due'], '%Y-%m-%d').date(),
        status='Assignment'
    )
    db.session.add(teacher_task)
    db.session.flush()

    students = User.query.filter_by(role='student').all()
    for student in students:
        student_task = Task(
            user_id=student.id,
            title=data['title'],
            description=data.get('description', 'No description provided.'),
            due_date=datetime.strptime(data['due'], '%Y-%m-%d').date(),
            status='Ongoing'
        )
        db.session.add(student_task)

    db.session.commit()
    return jsonify({'message': 'Assignment created and distributed to students!', 'id': teacher_task.id}), 201

@app.route('/api/tasks/<int:task_id>/complete', methods=['PUT'])
@token_required
def complete_task(task_id):
    task = Task.query.filter_by(id=task_id, user_id=g.current_user.id).first()
    
    if not task:
        return jsonify({'message': 'Task not found.'}), 404

    task.status = 'Completed'
    db.session.commit()
    return jsonify({'message': 'Task marked as completed!'}), 200

# --- SUBMISSION ENDPOINTS ---

@app.route('/api/submissions/<int:task_id>/submit', methods=['POST'])
@token_required
@role_required('student')
def submit_task(task_id):
    task = Task.query.filter_by(id=task_id, user_id=g.current_user.id).first()
    
    if not task:
        return jsonify({'message': 'Task not found or not assigned to user.'}), 404

    if task.status != 'Ongoing':
         return jsonify({'message': 'Task already submitted or completed.'}), 400
         
    if 'submission_file' not in request.files:
        return jsonify({'message': 'No file part in the request.'}), 400
        
    file = request.files['submission_file']
    
    if file.filename == '':
        return jsonify({'message': 'No selected file.'}), 400
        
    submitted_file = secure_filename(file.filename)
        
    task.status = 'Completed'

    new_submission = Submission(
        task_id=task_id,
        student_id=g.current_user.id,
        submitted_file=submitted_file, 
        status='Submitted'
    )
    
    db.session.add(new_submission)
    db.session.commit()
    return jsonify({'message': f'Assignment submitted successfully: {submitted_file}'}), 200

@app.route('/api/submissions', methods=['GET'])
@token_required
@role_required('teacher')
def get_submissions():
    student_tasks = Task.query.filter(Task.status != 'Assignment').all()
    student_task_ids = [t.id for t in student_tasks]
    
    submissions = Submission.query.filter(Submission.task_id.in_(student_task_ids)).order_by(Submission.date_submitted.desc()).all()
    
    output = []
    for sub in submissions:
         student_task = Task.query.filter_by(id=sub.task_id).first()
         student = User.query.filter_by(id=sub.student_id).first()
         
         if student_task and student:
             output.append({
                 'id': sub.id,
                 'task_id': sub.task_id,
                 'student_name': student.name,
                 'assignment_title': student_task.title,
                 'due_date': student_task.due_date.strftime('%Y-%m-%d'),
                 'submitted_file': sub.submitted_file,
                 'status': sub.status,
                 'grade': sub.grade,
                 'teacher_comment': sub.teacher_comment
             })
    return jsonify(output)

@app.route('/api/submissions/<int:submission_id>/grade', methods=['PUT'])
@token_required
@role_required('teacher')
def grade_submission(submission_id):
    data = request.get_json()
    grade = data.get('grade')
    teacher_comment = data.get('teacher_comment')
    
    if grade is None or not (0 <= grade <= 100):
        return jsonify({'message': 'Grade must be a number between 0 and 100.'}), 400

    submission = Submission.query.filter_by(id=submission_id).first()
    
    if not submission:
        return jsonify({'message': 'Submission not found.'}), 404
        
    submission.grade = grade
    submission.status = 'Graded'
    submission.teacher_comment = teacher_comment
    
    student_task = Task.query.filter_by(id=submission.task_id).first()
    if student_task:
        student_task.status = f'Graded: {grade}%'
    
    try:
        db.session.commit()
        return jsonify({'message': f'Submission {submission_id} graded at {grade}%.', 'status': 'Graded'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error grading submission: {e}'}), 500

# --- EVENT ENDPOINTS ---

@app.route('/api/events', methods=['GET'])
@token_required
def get_events():
    events = Event.query.filter_by(user_id=g.current_user.id).all()
    output = []
    for event in events:
        output.append({
            'id': event.id,
            'title': event.title,
            'date': event.date.strftime('%Y-%m-%d'),
            'type': event.type
        })
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

# --- STUDY TOOLS ENDPOINTS ---

@app.route('/api/flashcards', methods=['GET'])
@token_required
def get_flashcards():
    flashcards = Flashcard.query.filter_by(user_id=g.current_user.id).all()
    output = []
    for card in flashcards:
        output.append({
            'id': card.id,
            'front': card.front,
            'back': card.back
        })
    return jsonify(output)

@app.route('/api/flashcards', methods=['POST'])
@token_required
def create_flashcard():
    data = request.get_json()
    if not data.get('front') or not data.get('back'):
        return jsonify({'message': 'Front and back fields are required.'}), 400

    new_card = Flashcard(
        user_id=g.current_user.id,
        front=data['front'],
        back=data['back']
    )
    db.session.add(new_card)
    db.session.commit()
    return jsonify({'message': 'Flashcard created!', 'id': new_card.id}), 201

# --- RESOURCE ENDPOINTS ---

@app.route('/api/resources/upload', methods=['POST'])
@token_required
@role_required('teacher')
def upload_resource():
    if 'resource_file' not in request.files:
        return jsonify({'message': 'No file part in the request.'}), 400
        
    file = request.files['resource_file']
    class_name = request.form.get('class_name', 'All Classes')

    if file.filename == '':
        return jsonify({'message': 'No selected file.'}), 400
        
    secured_filename = secure_filename(file.filename)
    
    new_resource = ResourceFile(
        teacher_id=g.current_user.id,
        file_name=secured_filename,
        file_path=f"mock_storage/{g.current_user.id}/{secured_filename}",
        class_name=class_name
    )
    
    db.session.add(new_resource)
    db.session.commit()
    
    return jsonify({'message': f'Resource "{secured_filename}" uploaded successfully to {class_name}!', 'id': new_resource.id}), 201

@app.route('/api/resources', methods=['GET'])
@token_required
def get_resources():
    output = []
    
    if g.current_user.role == 'teacher':
        resources = ResourceFile.query.filter_by(teacher_id=g.current_user.id).order_by(ResourceFile.date_uploaded.desc()).all()
    else:
        resources = ResourceFile.query.filter_by(class_name='All Classes').order_by(ResourceFile.date_uploaded.desc()).all()
        
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

# --- ECO LOG ENDPOINTS ---

@app.route('/api/eco-log/action/<string:action_type>', methods=['POST'])
@token_required
def log_eco_action(action_type):
    if action_type not in ['waste', 'energy', 'transport']:
        return jsonify({'message': 'Invalid action type.'}), 400

    date_key = datetime.utcnow().date()

    log = EcoLog.query.filter_by(user_id=g.current_user.id, date=date_key).first()

    # If no log exists, create one with defaults
    if not log:
        log = EcoLog(
            user_id=g.current_user.id,
            date=date_key,
            waste_count=0,
            energy_count=0,
            transport_count=0,
            score=0
        )
        db.session.add(log)
    else:
        # Fix NULL values in older rows
        if log.waste_count is None:
            log.waste_count = 0
        if log.energy_count is None:
            log.energy_count = 0
        if log.transport_count is None:
            log.transport_count = 0
        if log.score is None:
            log.score = 0

    score_increment = 0

    if action_type == 'waste':
        log.waste_count += 1
        score_increment = 5
    elif action_type == 'energy':
        log.energy_count += 1
        score_increment = 5
    elif action_type == 'transport':
        log.transport_count += 1
        score_increment = 10

    log.score += score_increment

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
    date_str = request.args.get('date', datetime.utcnow().strftime('%Y-%m-%d'))
    try:
        date_key = datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        return jsonify({'message': 'Invalid date format. Use YYYY-MM-DD.'}), 400
    
    log = EcoLog.query.filter_by(user_id=g.current_user.id, date=date_key).first()
    
    if not log:
        return jsonify({ 'waste': 0, 'energy': 0, 'transport': 0, 'score': 0 }), 200

    return jsonify({
        'waste': log.waste_count,
        'energy': log.energy_count,
        'transport': log.transport_count,
        'score': log.score
    })

# --- TEACHER/CLASS ENDPOINTS ---

@app.route('/api/classes', methods=['GET'])
@token_required
@role_required('teacher')
def get_classes():
    classes = Class.query.filter_by(teacher_id=g.current_user.id).all()
    output = []
    for cls in classes:
        output.append({
            'id': cls.id,
            'name': cls.name,
            'estimated_students': cls.estimated_students
        })
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

# --- ANNOUNCEMENTS ENDPOINTS ---

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
        announcements = Announcement.query.order_by(Announcement.date_posted.desc()).all()
    else:
        announcements = Announcement.query.filter_by(teacher_id=g.current_user.id).order_by(Announcement.date_posted.desc()).all()
        
    output = []
    for ann in announcements:
        output.append({
            'id': ann.id,
            'title': ann.title,
            'message': ann.message,
            'recipient': ann.recipient,
            'date': ann.date_posted.strftime('%Y-%m-%d')
        })
    return jsonify(output)

# --- DB INIT COMMAND ---

@app.cli.command("init-db")
def init_db():
    try:
        with app.app_context():
            db.drop_all()
            db.create_all()

            mock_teacher = User(name="Alex Johnson (Teacher)", email="teacher@stuflow.com", role="teacher")
            mock_teacher.set_password("password")
            db.session.add(mock_teacher)

            mock_student = User(name="Sam Smith (Student)", email="student@stuflow.com", role="student")
            mock_student.set_password("password")
            db.session.add(mock_student)

            db.session.commit()

        print("Database initialized successfully!")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    app.run(debug=True)


