from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
from flask import Blueprint
from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager  # Import JWTManager
from flask_migrate import Migrate
from flask import Blueprint
from database import db
from models import TriviaQuestion, User, Feedback, Notification, QuizSession
from config import Config
import random
from auth import auth_bp  # Import authentication routes
from auth import auth_bp, check_if_token_is_blacklisted

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

# Initialize security features
app.config['JWT_SECRET_KEY'] = 'e2ad644a426839bef2fd2284791e6b9f9aada3ea8a8445b8c2995aaf7da8e6b4'  # Change this to a strong secret
jwt = JWTManager(app)
bcrypt = Bcrypt(app)

# Register the blacklist function
@jwt.token_in_blocklist_loader
def is_token_blacklisted(jwt_header, jwt_payload):
    return check_if_token_is_blacklisted(jwt_header, jwt_payload)

# Register authentication routes
app.register_blueprint(auth_bp)

# Initialize migration
migrate = Migrate(app, db)

# Create database tables
with app.app_context():
    db.create_all()

# ✅ Create a new trivia question (POST)
@app.route('/trivia/questions', methods=['POST'])
def add_question():
    data = request.json
    new_question = TriviaQuestion(
        category=data['category'],
        question=data['question'],
        answer=data['answer'],
        difficulty=data['difficulty']
    )
    db.session.add(new_question)
    db.session.commit()
    return jsonify({'message': 'Question added successfully'}), 201

# ✅ Get a trivia question by ID (GET)
@app.route('/trivia/questions/<int:question_id>', methods=['GET'])
def get_question_by_id(question_id):
    question = TriviaQuestion.query.get(question_id)
    if not question:
        return jsonify({'error': 'Question not found'}), 404
    return jsonify({
        'id': question.id,
        'question': question.question,
        'answer': question.answer,
        'category': question.category,
        'difficulty': question.difficulty,
        'explanation': question.explanation if question.explanation else "No explanation available"
    })

# ✅ Retrieve tags for a trivia question (GET)
@app.route('/trivia/questions/<int:question_id>/tags', methods=['GET'])
def get_question_tags(question_id):
    question = TriviaQuestion.query.get(question_id)
    
    if not question:
        return jsonify({'error': 'Question not found'}), 404

    if not question.tags:
        return jsonify({'message': 'No tags available for this question'}), 404

    return jsonify({'question': question.question, 'tags': question.tags.split(", ")})

# ✅ Update or add tags for a trivia question (PUT)
@app.route('/trivia/questions/<int:question_id>/tags', methods=['PUT'])
def update_question_tags(question_id):
    data = request.json
    tags = data.get('tags')  # Expecting a list of tags

    question = TriviaQuestion.query.get(question_id)
    if not question:
        return jsonify({'error': 'Question not found'}), 404

    question.tags = ", ".join(tags)  # Store tags as comma-separated values
    db.session.commit()

    return jsonify({'message': 'Tags updated successfully', 'tags': tags})

# ✅ Retrieve all trivia questions (GET)
@app.route('/trivia/questions', methods=['GET'])
def get_questions():
    questions = TriviaQuestion.query.all()
    return jsonify([{'id': q.id, 'question': q.question, 'category': q.category, 'answer': q.answer} for q in questions])

# ✅ Update a trivia question (PUT)
@app.route('/trivia/questions/<int:question_id>', methods=['PUT'])
def update_question(question_id):
    question = TriviaQuestion.query.get(question_id)
    if not question:
        return jsonify({'error': 'Question not found'}), 404

    data = request.json
    question.question = data.get('question', question.question)
    question.answer = data.get('answer', question.answer)
    question.category = data.get('category', question.category)
    question.difficulty = data.get('difficulty', question.difficulty)
    question.explanation = data.get('explanation', question.explanation)  # ✅ Ensure explanation updates

    db.session.commit()
    return jsonify({'message': 'Question updated successfully'})


# ✅ Delete a trivia question (DELETE)
@app.route('/trivia/questions/<int:question_id>', methods=['DELETE'])
def delete_question(question_id):
    question = TriviaQuestion.query.get(question_id)
    if not question:
        return jsonify({'error': 'Question not found'}), 404

    db.session.delete(question)
    db.session.commit()
    return jsonify({'message': 'Question deleted successfully'})

# ✅ Retrieve all trivia categories (GET)
@app.route('/trivia/categories', methods=['GET'])
def get_categories():
    categories = ["Science", "History", "Sports", "Entertainment", "Geography"]
    return jsonify({"categories": categories})

# ✅ Get a random trivia question (GET)
@app.route('/trivia/questions/random', methods=['GET'])
def get_random_question():
    questions = TriviaQuestion.query.all()
    if not questions:
        return jsonify({'message': 'No questions available'}), 404
    question = random.choice(questions)
    return jsonify({
        'id': question.id,
        'category': question.category,
        'question': question.question,
        'answer': question.answer,
        'difficulty': question.difficulty
    })

# ✅ Get a random trivia question from a specific category (GET)
@app.route('/trivia/questions/<string:category>/random', methods=['GET'])
def get_random_question_by_category(category):
    questions = TriviaQuestion.query.filter_by(category=category).all()
    if not questions:
        return jsonify({'message': 'No questions available in this category'}), 404
    question = random.choice(questions)
    return jsonify({
        'id': question.id,
        'category': question.category,
        'question': question.question,
        'answer': question.answer,
        'difficulty': question.difficulty
    })

# ✅ Get the total number of questions available in a specific category (GET)
@app.route('/trivia/questions/<string:category>/count', methods=['GET'])
def get_question_count_by_category(category):
    count = TriviaQuestion.query.filter(TriviaQuestion.category.ilike(category)).count()
    if count == 0:
        return jsonify({'message': f'No questions found in category: {category}'}), 404
    return jsonify({'category': category, 'question_count': count})

# ✅ Get the correct answer for a trivia question (GET)
@app.route('/trivia/questions/<int:question_id>/answer', methods=['GET'])
def get_answer(question_id):
    question = TriviaQuestion.query.get(question_id)
    if not question:
        return jsonify({'error': 'Question not found'}), 404
    return jsonify({'question': question.question, 'correct_answer': question.answer})

# ✅ Retrieve trivia questions filtered by difficulty level (easy, medium, hard) (GET)
@app.route('/trivia/questions/<string:category>/<string:difficulty>', methods=['GET'])
def get_questions_by_difficulty(category, difficulty):
    questions = TriviaQuestion.query.filter(
        TriviaQuestion.category.ilike(category),
        TriviaQuestion.difficulty.ilike(difficulty)
    ).all()

    if not questions:
        return jsonify({'message': f'No {difficulty} questions found in category: {category}'}), 404

    return jsonify([
        {'id': q.id, 'question': q.question, 'answer': q.answer, 'difficulty': q.difficulty}
        for q in questions
    ])

# ✅ Get hints for a trivia question (GET)
@app.route('/trivia/questions/<int:question_id>/hints', methods=['GET'])
def get_hints(question_id):
    question = TriviaQuestion.query.get(question_id)
    if not question:
        return jsonify({'error': 'Question not found'}), 404
    hint = f"The answer starts with '{question.answer[0]}' and ends with '{question.answer[-1]}'"
    return jsonify({'question': question.question, 'hint': hint})

# ✅ Get leaderboard (GET)
@app.route('/trivia/leaderboard', methods=['GET'])
def get_leaderboard():
    top_users = User.query.order_by(User.score.desc()).limit(10).all()
    leaderboard = [{'username': user.username, 'score': user.score} for user in top_users]
    return jsonify({'leaderboard': leaderboard})

# ✅ Get user score history (GET)
@app.route('/trivia/score/<int:user_id>', methods=['GET'])
def get_user_score(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'username': user.username, 'score': user.score})

# ✅ Update user score (PUT)
@app.route('/trivia/score/update', methods=['PUT'])
@jwt_required()  # Requires authentication
def update_score():
    user_id = get_jwt_identity()  # Get logged-in user
    data = request.json
    points = data.get('points')

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    user.score += points
    db.session.commit()
    return jsonify({'message': 'Score updated successfully', 'new_score': user.score})

# ✅ Get quiz history (GET)
@app.route('/trivia/user/<int:user_id>/history', methods=['GET'])
@jwt_required()
def get_user_quiz_history(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Get past quiz sessions
    past_quizzes = QuizSession.query.filter_by(user_id=user_id, is_active=False).all()

    history_data = []
    for quiz in past_quizzes:
        history_data.append({
            "quiz_id": quiz.id,
            "score": quiz.score,
            "questions": quiz.get_question_list(),
            "date_played": quiz.created_at.strftime("%Y-%m-%d %H:%M:%S")
        })

    return jsonify({"username": user.username, "quiz_history": history_data})

# ✅ Suggest Similar Trivia Questions (GET)
@app.route('/trivia/questions/similar/<int:question_id>', methods=['GET'])
def get_similar_questions(question_id):
    question = TriviaQuestion.query.get(question_id)
    if not question:
        return jsonify({'error': 'Question not found'}), 404

    # Get similar questions in the same category (excluding itself)
    similar_questions = TriviaQuestion.query.filter(
        TriviaQuestion.category == question.category, TriviaQuestion.id != question_id
    ).limit(3).all()

    return jsonify({
        "question": question.question,
        "similar_questions": [{"id": q.id, "question": q.question} for q in similar_questions]
    })

# ✅ Submit feedback (POST)
@app.route('/trivia/feedback', methods=['POST'])
@jwt_required()
def submit_feedback():
    data = request.json
    user_id = get_jwt_identity()
    question_id = data.get('question_id')
    comment = data.get('comment')

    if not question_id or not comment:
        return jsonify({'error': 'Question ID and comment are required'}), 400

    feedback = Feedback(user_id=user_id, question_id=question_id, comment=comment)
    db.session.add(feedback)
    db.session.commit()

    return jsonify({'message': 'Feedback submitted successfully'})

# ✅ View Submitted Feedback (GET)
@app.route('/trivia/feedback/<int:question_id>', methods=['GET'])
def get_feedback(question_id):
    question = TriviaQuestion.query.get(question_id)
    if not question:
        return jsonify({'error': 'Question not found'}), 404

    feedbacks = Feedback.query.filter_by(question_id=question_id).all()
    
    if not feedbacks:
        return jsonify({'message': 'No feedback available for this question'}), 404

    feedback_data = [{"user_id": f.user_id, "comment": f.comment, "date": f.created_at.strftime("%Y-%m-%d %H:%M:%S")} for f in feedbacks]

    return jsonify({
        "question": question.question,
        "feedback": feedback_data
    })

# ✅ ANSWERS!
@app.route('/trivia/quiz/answer', methods=['POST'])
@jwt_required()
def answer_multiple_questions():
    user_id = get_jwt_identity()
    data = request.json
    quiz_id = data.get('quiz_id')
    answers = data.get('answers')  # Expecting a list of answers

    # Find active quiz session
    session = QuizSession.query.filter_by(id=quiz_id, user_id=user_id, is_active=True).first()
    if not session:
        return jsonify({'error': 'No active quiz session found'}), 404

    results = {}  # Store question results
    score = 0  # Track correct answers

    for item in answers:
        question_id = item['question_id']
        user_answer = item['answer']

        # Fetch the question
        question = TriviaQuestion.query.get(question_id)
        if not question:
            results[f"Question {question_id}"] = {"question": "Not found", "correct": False}
            continue

        # Check answer correctness
        is_correct = (question.answer.lower() == user_answer.lower())
        results[f"Question {question_id}"] = {"question": question.question, "correct": is_correct}

        # Update score
        if is_correct:
            score += 5

    # Update quiz session score
    session.score = score
    db.session.commit()

    return jsonify({
        "message": "Answers submitted!",
        "quiz_id": quiz_id,
        "results": results
    })

# ✅ Recommend Trivia Categories (GET)
@app.route('/trivia/quiz/recommendations', methods=['GET'])
@jwt_required()
def get_recommendations():
    # Get top categories based on quiz history
    top_categories = db.session.query(
        TriviaQuestion.category, db.func.count(TriviaQuestion.id)
    ).group_by(TriviaQuestion.category).order_by(db.func.count(TriviaQuestion.id).desc()).limit(3).all()

    return jsonify({
        "recommended_categories": [cat[0] for cat in top_categories]
    })

# ✅ Get explanation for a trivia question (GET)
@app.route('/trivia/questions/<int:question_id>/explanation', methods=['GET'])
def get_question_explanation(question_id):
    question = TriviaQuestion.query.get(question_id)
    if not question:
        return jsonify({'error': 'Question not found'}), 404
    if not question.explanation:
        return jsonify({'message': 'No explanation available'}), 404
    return jsonify({'question': question.question, 'explanation': question.explanation})

# ✅ Start a new trivia quiz session for a user (POST)
@app.route('/trivia/quiz/start', methods=['POST'])
@jwt_required()  # Requires user authentication
def start_quiz():
    user_id = get_jwt_identity()  # Get logged-in user
    data = request.json
    num_questions = data.get('num_questions', 5)  # Default to 5 questions

    # Check if the user already has an active quiz session
    active_session = QuizSession.query.filter_by(user_id=user_id, is_active=True).first()
    if active_session:
        return jsonify({'error': 'You already have an active quiz session'}), 400

    # Select random trivia questions
    questions = TriviaQuestion.query.order_by(db.func.random()).limit(num_questions).all()
    if not questions:
        return jsonify({'error': 'No trivia questions available'}), 404

    question_ids = [q.id for q in questions]

    # Create a new quiz session
    new_session = QuizSession(user_id=user_id)
    new_session.set_question_list(question_ids)
    db.session.add(new_session)
    db.session.commit()

    return jsonify({
        'message': 'Quiz started successfully!',
        'quiz_id': new_session.id,
        'questions': [{'id': q.id, 'question': q.question, 'category': q.category} for q in questions]
    })

# ✅ End the current trivia quiz session and calculate the final score (POST)
@app.route('/trivia/quiz/end', methods=['POST'])
@jwt_required()
def end_quiz():
    user_id = get_jwt_identity()  # Get logged-in user
    data = request.json
    quiz_id = data.get('quiz_id')

    # Find the active quiz session
    session = QuizSession.query.filter_by(id=quiz_id, user_id=user_id, is_active=True).first()
    if not session:
        return jsonify({'error': 'No active quiz session found'}), 404

    # Mark the quiz as completed
    session.is_active = False

    # Update the user's total score
    user = User.query.get(user_id)
    user.score += session.score

    db.session.commit()

    return jsonify({'message': 'Quiz ended successfully', 'final_score': session.score, 'total_score': user.score})

# ✅ Manage notifications (POST, DELETE)
@app.route('/trivia/notifications', methods=['POST'])
@jwt_required()
def add_notification():
    data = request.json
    user_id = get_jwt_identity()
    notification = Notification(user_id=user_id, message=data['message'])
    db.session.add(notification)
    db.session.commit()
    return jsonify({'message': 'Notification added successfully'})

@app.route('/trivia/notifications/<int:user_id>', methods=['DELETE'])
def delete_notification(user_id):
    notifications = Notification.query.filter_by(user_id=user_id).all()
    for notif in notifications:
        db.session.delete(notif)
    db.session.commit()
    return jsonify({'message': 'Notifications deleted successfully'})

if __name__ == '__main__':
    app.run(debug=True)
