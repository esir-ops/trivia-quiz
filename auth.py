from flask import Blueprint, request, jsonify
from database import db
from models import User, QuizHistory, Feedback, Notification, QuizSession
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    create_access_token, jwt_required, get_jwt_identity, get_jwt
)
import datetime
from sqlalchemy import text

auth_bp = Blueprint('auth', __name__)
bcrypt = Bcrypt()

blacklisted_tokens = set()

@auth_bp.route('/auth/register', methods=['POST'])
def register():
    data = request.json
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password are required'}), 400
    username = data.get('username').strip()
    password = data.get('password').strip()
    if not username or not password:
        return jsonify({'error': 'Username and password cannot be empty'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 400
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

@auth_bp.route('/auth/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid username or password'}), 401
    access_token = create_access_token(identity=str(user.id))
    notifications = Notification.query.filter_by(user_id=user.id, read=False).all()
    notification_list = []
    known_categories = ["science", "sports", "history", "entertainment", "geography"]
    for notif in notifications:
        lower_msg = notif.message.lower()
        found_category = None
        for cat in known_categories:
            if cat in lower_msg:
                found_category = cat
                break
        if found_category:
            new_cat_questions = db.session.execute(
                text("SELECT id FROM trivia_question WHERE lower(category) = lower(:cat) AND created_at >= :notif_time"),
                {"cat": found_category, "notif_time": notif.created_at}
            ).fetchall()
            if new_cat_questions and len(new_cat_questions) > 0:
                notif.message = f"New {found_category.capitalize()} questions added!"
        else:
            if "trivia questions" in lower_msg:
                new_questions = db.session.execute(
                    text("SELECT id FROM trivia_question WHERE created_at >= :notif_time"),
                    {"notif_time": notif.created_at}
                ).fetchall()
                if new_questions and len(new_questions) > 0:
                    notif.message = "New trivia questions added!"
        notification_list.append({
            "id": notif.id,
            "message": notif.message,
            "date": notif.created_at.strftime("%Y-%m-%d %H:%M:%S")
        })
        if "notify me when" not in lower_msg:
            notif.read = True
    db.session.commit()
    return jsonify({
        'message': 'Login successful',
        'access_token': access_token,
        'user_id': user.id,
        'notifications': notification_list
    })

@auth_bp.route('/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    blacklisted_tokens.add(jti)
    return jsonify({"message": "Successfully logged out"}), 200

def check_if_token_is_blacklisted(jwt_header, jwt_payload):
    return jwt_payload["jti"] in blacklisted_tokens

@auth_bp.route('/auth/delete', methods=['DELETE'])
@jwt_required()
def delete_account():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    QuizHistory.query.filter_by(user_id=user_id).delete()
    Feedback.query.filter_by(user_id=user_id).delete()
    Notification.query.filter_by(user_id=user_id).delete()
    QuizSession.query.filter_by(user_id=user_id).delete()
    db.session.delete(user)
    db.session.commit()
    jti = get_jwt()["jti"]
    blacklisted_tokens.add(jti)
    return jsonify({"message": "Account deleted successfully"}), 200
