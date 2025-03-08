from database import db
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()  # Initialize bcrypt for password hashing

class TriviaQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(100), nullable=False)
    question = db.Column(db.String(500), nullable=False)
    answer = db.Column(db.String(200), nullable=False)
    difficulty = db.Column(db.String(20), nullable=False)
    explanation = db.Column(db.String(1000), nullable=True)
    feedbacks = db.relationship('Feedback', backref='question', lazy=True)  # Relationship
    tags = db.Column(db.String(300), nullable=True)
    
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Securely store hashed password
    score = db.Column(db.Integer, default=0)  
    history = db.relationship('QuizHistory', backref='user', lazy=True)
    feedbacks = db.relationship('Feedback', backref='user', lazy=True)
    notifications = db.relationship('Notification', backref='user', lazy=True)

    def set_password(self, password):
        """Hashes the password before storing it."""
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        """Verifies the hashed password."""
        return bcrypt.check_password_hash(self.password, password)

class QuizSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question_ids = db.Column(db.String(500), nullable=False)  # Store question IDs as comma-separated values
    score = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    def get_question_list(self):
        return [int(q) for q in self.question_ids.split(',') if q]

    def set_question_list(self, question_list):
        self.question_ids = ','.join(map(str, question_list))

class QuizHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('trivia_question.id'), nullable=False)
    is_correct = db.Column(db.Boolean, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())  # Track when answered

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('trivia_question.id'), nullable=False)
    comment = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
