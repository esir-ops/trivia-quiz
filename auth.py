from flask import Blueprint, request, jsonify
from database import db
from models import User, QuizHistory, Feedback, Notification
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    create_access_token, jwt_required, get_jwt_identity, get_jwt
)

auth_bp = Blueprint('auth', __name__)
bcrypt = Bcrypt()

# Store blacklisted tokens (this should ideally be in a database)
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
    return jsonify({'message': 'Login successful', 'access_token': access_token})

@auth_bp.route('/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    blacklisted_tokens.add(jti)
    return jsonify({"message": "Successfully logged out"}), 200

def check_if_token_is_blacklisted(jwt_header, jwt_payload):
    return jwt_payload["jti"] in blacklisted_tokens  # Deny access to blacklisted tokens

@auth_bp.route('/auth/delete', methods=['DELETE'])  # ✅ Ensure DELETE method is properly registered
@jwt_required()
def delete_account():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404

    # Delete related data
    QuizHistory.query.filter_by(user_id=user_id).delete()
    Feedback.query.filter_by(user_id=user_id).delete()
    Notification.query.filter_by(user_id=user_id).delete()

    # Delete the user account
    db.session.delete(user)
    db.session.commit()

    # Blacklist token
    jti = get_jwt()["jti"]
    blacklisted_tokens.add(jti)

    return jsonify({"message": "Account deleted successfully"}), 200
