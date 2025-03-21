import json
from collections import OrderedDict
import random
from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
)
from flask_migrate import Migrate
from database import db
from models import TriviaQuestion, User, Feedback, Notification, QuizSession, QuizHistory
from config import Config
from auth import auth_bp, check_if_token_is_blacklisted
import datetime
from sqlalchemy import text

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
app.config['JWT_SECRET_KEY'] = 'e2ad644a426839bef2fd2284791e6b9f9aada3ea8a8445b8c2995aaf7da8e6b4'
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)

@jwt.token_in_blocklist_loader
def is_token_blacklisted(jwt_header, jwt_payload):
    return check_if_token_is_blacklisted(jwt_header, jwt_payload)

app.register_blueprint(auth_bp)

with app.app_context():
    db.create_all()

# -------------------- Trivia Question Endpoints --------------------

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
    notifications = Notification.query.filter(
        Notification.message.ilike(f"%{new_question.category}%")
    ).all()
    for notif in notifications:
        notif.message = f"New added question in {new_question.category}!!!"
    db.session.commit()
    return jsonify({'message': 'Question added successfully'}), 201

@app.route('/trivia/questions/<int:question_id>', methods=['GET'])
def get_question_by_id(question_id):
    question = TriviaQuestion.query.get(question_id)
    if not question:
        return jsonify({'error': 'Question not found'}), 404
    return jsonify({
        'id': question.id,
        'question': question.question,
        'category': question.category,
        'difficulty': question.difficulty
    })

@app.route('/trivia/questions/<int:question_id>/tags', methods=['GET'])
def get_question_tags(question_id):
    question = TriviaQuestion.query.get(question_id)
    if not question:
        return jsonify({'error': 'Question not found'}), 404
    if not question.tags:
        return jsonify({'message': 'No tags available for this question'}), 404
    return jsonify({'question': question.question, 'tags': question.tags.split(", ")})

@app.route('/trivia/questions/<int:question_id>/tags', methods=['PUT'])
def update_question_tags(question_id):
    data = request.json
    tags = data.get('tags')
    question = TriviaQuestion.query.get(question_id)
    if not question:
        return jsonify({'error': 'Question not found'}), 404
    question.tags = ", ".join(tags)
    db.session.commit()
    return jsonify({'message': 'Tags updated successfully', 'tags': tags})

@app.route('/trivia/questions', methods=['GET'])
def get_questions():
    questions = TriviaQuestion.query.all()
    return jsonify([{'id': q.id, 'question': q.question, 'category': q.category} for q in questions])

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
    question.explanation = data.get('explanation', question.explanation)
    db.session.commit()
    return jsonify({'message': 'Question updated successfully'})

@app.route('/trivia/questions/<int:question_id>', methods=['DELETE'])
def delete_question(question_id):
    question = TriviaQuestion.query.get(question_id)
    if not question:
        return jsonify({'error': 'Question not found'}), 404
    db.session.delete(question)
    db.session.commit()
    return jsonify({'message': 'Question deleted successfully'})

@app.route('/trivia/categories', methods=['GET'])
def get_categories():
    categories = ["Science", "History", "Sports", "Entertainment", "Geography"]
    return jsonify({"categories": categories})

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
        'difficulty': question.difficulty
    })

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
        'difficulty': question.difficulty
    })

@app.route('/trivia/questions/<string:category>/count', methods=['GET'])
def get_question_count_by_category(category):
    count = TriviaQuestion.query.filter(TriviaQuestion.category.ilike(category)).count()
    if count == 0:
        return jsonify({'message': f'No questions found in category: {category}'}), 404
    return jsonify({'category': category, 'question_count': count})

@app.route('/trivia/questions/<string:category>/<string:difficulty>', methods=['GET'])
def get_questions_by_difficulty(category, difficulty):
    questions = TriviaQuestion.query.filter(
        TriviaQuestion.category.ilike(category),
        TriviaQuestion.difficulty.ilike(difficulty)
    ).all()
    if not questions:
        return jsonify({'message': f'No {difficulty} questions found in category: {category}'}), 404
    return jsonify([{'id': q.id, 'question': q.question, 'answer': q.answer, 'difficulty': q.difficulty} for q in questions])

def normalize_answer(answer):
    return " ".join(answer.strip().lower().split())

@app.route('/trivia/questions/<int:question_id>/hints', methods=['GET'])
def get_hints(question_id):
    question = TriviaQuestion.query.get(question_id)
    if not question:
        return jsonify({'error': 'Question not found'}), 404

    answer_words = question.answer.split()
    word_count = len(answer_words)
    first_letters = ", ".join([word[0] for word in answer_words])
    last_letters = ", ".join([word[-1] for word in answer_words])
    
    hint_str = f"The answer consists of {word_count} word{'s' if word_count != 1 else ''}. " \
               f"The first letter{' is' if word_count == 1 else 's are'}: {first_letters}; " \
               f"the last letter{' is' if word_count == 1 else 's are'}: {last_letters}."
    
    return jsonify({
        'question': question.question,
        'word_count': word_count,
        'hint': hint_str
    })

@app.route('/trivia/questions/<int:question_id>/answer', methods=['POST'])
def submit_single_answer(question_id):
    data = request.json
    user_answer = data.get('answer')
    if not user_answer:
        return jsonify({'error': 'Answer is required'}), 400
    question = TriviaQuestion.query.get(question_id)
    if not question:
        return jsonify({'error': 'Question not found'}), 404
    normalized_correct = normalize_answer(question.answer)
    normalized_user = normalize_answer(user_answer)
    is_correct = (normalized_correct == normalized_user)
    feedback = "Correct!" if is_correct else "Incorrect. Try again."
    return jsonify({
        'question': question.question,
        'your_answer': user_answer,
        'correct_answer': question.answer,
        'is_correct': is_correct,
        'feedback': feedback
    })

@app.route('/trivia/questions/<int:question_id>/explanation', methods=['GET'])
def get_question_explanation(question_id):
    question = TriviaQuestion.query.get(question_id)
    if not question:
        return jsonify({'error': 'Question not found'}), 404
    if not question.explanation:
        return jsonify({'message': 'No explanation available'}), 404
    return jsonify({'question': question.question, 'explanation': question.explanation})

@app.route('/trivia/questions/<int:question_id>/explanation', methods=['PUT'])
def update_question_explanation(question_id):
    data = request.json
    explanation = data.get('explanation')
    if explanation is None:
        return jsonify({'error': 'Explanation is required'}), 400
    question = TriviaQuestion.query.get(question_id)
    if not question:
        return jsonify({'error': 'Question not found'}), 404
    question.explanation = explanation
    db.session.commit()
    return jsonify({
        'message': 'Explanation updated successfully',
        'question': question.question,
        'explanation': question.explanation
    })

@app.route('/trivia/questions/quiz', methods=['GET'])
def generate_quiz_set():
    num_questions = request.args.get('num_questions', default=5, type=int)
    questions = TriviaQuestion.query.order_by(db.func.random()).limit(num_questions).all()
    if not questions:
        return jsonify({'error': 'No trivia questions available'}), 404
    quiz_questions = []
    for q in questions:
        quiz_questions.append({
            "id": q.id,
            "question": q.question,
            "category": q.category,
            "difficulty": q.difficulty
        })
    response_data = OrderedDict()
    response_data["title"] = "#Quiz Practice Questions"
    response_data["quiz_questions"] = quiz_questions
    return app.response_class(
        json.dumps(response_data, ensure_ascii=False, sort_keys=False),
        mimetype='application/json'
    )

# -------------------- Score, History, and Leaderboard Endpoints --------------------

@app.route('/trivia/leaderboard', methods=['GET'])
def get_leaderboard():
    top_users = User.query.order_by(User.score.desc()).limit(10).all()
    leaderboard = [{'username': user.username, 'score': user.score} for user in top_users]
    return jsonify({'leaderboard': leaderboard})

@app.route('/trivia/score/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user_score_history(user_id):
    current_user_id = int(get_jwt_identity())
    if current_user_id != user_id:
        return jsonify({"error": "Access denied"}), 403
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    past_quizzes = QuizSession.query.filter_by(user_id=user_id, is_active=False).all()
    history = []
    for quiz in past_quizzes:
        bonus_value = quiz.bonus if quiz.bonus is not None else 0
        total_session_score = quiz.score + bonus_value
        history.append({
            "quiz_id": quiz.id,
            "raw_score": quiz.score,
            "bonus": quiz.bonus if quiz.bonus_applied else 0,
            "total_session_score": total_session_score,
            "date": quiz.created_at.strftime("%Y-%m-%d %H:%M:%S")
        })
    return jsonify({
        "username": user.username,
        "total_score": user.score,
        "score_history": history
    })

@app.route('/trivia/score/update', methods=['PUT'])
@jwt_required()
def update_score():
    user_id = int(get_jwt_identity())
    data = request.json
    quiz_id = data.get('quiz_id')
    if not quiz_id:
        return jsonify({'error': 'quiz_id is required'}), 400
    session = QuizSession.query.filter_by(id=quiz_id, user_id=user_id, is_active=False).first()
    if not session:
        return jsonify({'error': 'Completed quiz session not found'}), 404
    if session.bonus_applied:
        return jsonify({'error': 'Bonus for this quiz session has already been applied'}), 400
    bonus = 1 if session.score >= 10 else 0
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    user.score += bonus
    session.bonus = bonus
    session.bonus_applied = True
    db.session.commit()
    return jsonify({'message': 'Score updated successfully', 'new_total_score': user.score})

@app.route('/trivia/user/<int:user_id>/history', methods=['GET'])
@jwt_required()
def get_user_quiz_history(user_id):
    current_user_id = int(get_jwt_identity())
    if current_user_id != user_id:
        return jsonify({"error": "Access denied"}), 403
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    past_quizzes = QuizSession.query.filter_by(user_id=user_id, is_active=False).all()
    history_data = []
    for quiz in past_quizzes:
        raw_score = quiz.score if quiz.score >= 0 else 0
        bonus = quiz.bonus if quiz.bonus_applied else 0
        history_data.append({
            "quiz_id": quiz.id,
            "score": raw_score,
            "bonus": bonus,
            "total_session_score": raw_score + bonus,
            "questions": quiz.get_question_list(),
            "date_played": quiz.created_at.strftime("%Y-%m-%d %H:%M:%S")
        })
    return jsonify({
        "username": user.username,
        "total_score": user.score,
        "quiz_history": history_data
    })

# -------------------- Quiz Session Endpoints --------------------

@app.route('/trivia/quiz/start', methods=['POST'])
@jwt_required()
def start_quiz():
    user_id = get_jwt_identity()
    data = request.json
    num_questions = data.get('num_questions', 5)
    if num_questions > 10:
        return jsonify({'error': 'The maximum number of questions allowed is 10.'}), 400
    active_session = QuizSession.query.filter_by(user_id=user_id, is_active=True).first()
    if active_session:
        return jsonify({'error': 'You already have an active quiz session'}), 400
    questions = TriviaQuestion.query.order_by(db.func.random()).limit(num_questions).all()
    if not questions:
        return jsonify({'error': 'No trivia questions available'}), 404
    question_ids = [q.id for q in questions]
    new_session = QuizSession(user_id=user_id)
    new_session.set_question_list(question_ids)
    db.session.add(new_session)
    db.session.commit()
    return jsonify({
        'message': 'Quiz started successfully!',
        'quiz_id': new_session.id,
        'questions': [{'id': q.id, 'question': q.question, 'category': q.category} for q in questions]
    })

@app.route('/trivia/quiz/end', methods=['POST'])
@jwt_required()
def end_quiz():
    user_id = int(get_jwt_identity())
    data = request.json
    quiz_id = data.get('quiz_id')
    session = QuizSession.query.filter_by(id=quiz_id, user_id=user_id, is_active=True).first()
    if not session:
        return jsonify({'error': 'No active quiz session found'}), 404
    session.is_active = False
    user = User.query.get(user_id)
    user.score += session.score
    question_ids = session.get_question_list()
    quiz_details = []
    for qid in question_ids:
        question = TriviaQuestion.query.get(qid)
        if question:
            quiz_details.append({
                "id": question.id,
                "question": question.question,
                "category": question.category,
                "difficulty": question.difficulty,
                "correct_answer": question.answer
            })
    db.session.commit()
    return jsonify({
        "message": "Quiz ended successfully",
        "final_score": session.score,
        "total_score": user.score,
        "quiz_details": quiz_details
    })

@app.route('/trivia/quiz/answer', methods=['POST'])
@jwt_required()
def answer_multiple_questions():
    user_id = int(get_jwt_identity())
    data = request.json
    quiz_id = data.get('quiz_id')
    answers = data.get('answers')
    session = QuizSession.query.filter_by(id=quiz_id, user_id=user_id, is_active=True).first()
    if not session:
        return jsonify({'error': 'No active quiz session found'}), 404
    if session.answers_submitted:
        return jsonify({'error': 'Answers have already been submitted for this quiz session.'}), 400
    valid_question_ids = session.get_question_list()
    results = {}
    score = 0
    def normalize(text):
        return " ".join(text.strip().lower().split())
    for item in answers:
        question_id = item.get('question_id')
        user_answer = item.get('answer')
        if question_id not in valid_question_ids:
            results[f"Question {question_id}"] = {
                "question": "This question is not part of your active quiz session.",
                "correct": False
            }
            continue
        question = TriviaQuestion.query.get(question_id)
        if not question:
            results[f"Question {question_id}"] = {"question": "Not found", "correct": False}
            continue
        normalized_correct = normalize(question.answer)
        normalized_user = normalize(user_answer)
        is_correct = (normalized_correct == normalized_user)
        results[f"Question {question_id}"] = {
            "question": question.question,
            "your_answer": normalized_user,
            "correct": is_correct
        }
        if is_correct:
            score += 2
    session.score = score
    session.answers_submitted = True
    db.session.commit()
    return jsonify({
        "message": "Answers submitted!",
        "quiz_id": quiz_id,
        "results": results
    })

# -------------------- Quiz Recommendations --------------------

@app.route('/trivia/quiz/recommendations', methods=['GET'])
@jwt_required()
def get_recommendations():
    user_id = get_jwt_identity()
    past_quizzes = QuizSession.query.filter_by(user_id=user_id, is_active=False).all()
    category_stats = {}
    for quiz in past_quizzes:
        question_ids = quiz.get_question_list()
        for qid in question_ids:
            question = TriviaQuestion.query.get(qid)
            if not question:
                continue
            category = question.category
            if category not in category_stats:
                category_stats[category] = {"correct": 0, "total": 0}
            category_stats[category]["total"] += 1
            if quiz.score > 0:
                category_stats[category]["correct"] += 1
    sorted_categories = sorted(
        category_stats.items(),
        key=lambda x: x[1]["correct"],
        reverse=True
    )[:3]
    user = User.query.get(user_id)
    recommendations = []
    for category, stats in sorted_categories:
        accuracy = (stats["correct"] / stats["total"]) * 100 if stats["total"] > 0 else 0
        recommendations.append({
            "category": category,
            "correct_answers": stats["correct"],
            "total_answered": stats["total"],
            "accuracy": f"{accuracy:.1f}%"
        })
    return jsonify({
        "username": user.username,
        "recommended_categories": recommendations,
        "note": "Based on your correct answers from previous quizzes."
    })

# -------------------- Suggest Similar Questions --------------------

@app.route('/trivia/questions/similar/<int:question_id>', methods=['GET'])
def get_similar_questions(question_id):
    question = TriviaQuestion.query.get(question_id)
    if not question:
        return jsonify({'error': 'Question not found'}), 404
    similar_questions = TriviaQuestion.query.filter(
        TriviaQuestion.category == question.category, TriviaQuestion.id != question_id
    ).limit(3).all()
    return jsonify({
        "question": question.question,
        "similar_questions": [{"id": q.id, "question": q.question} for q in similar_questions]
    })

# -------------------- Feedback Endpoints --------------------

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

@app.route('/trivia/feedback/<int:question_id>', methods=['GET'])
def get_feedback(question_id):
    question = TriviaQuestion.query.get(question_id)
    if not question:
        return jsonify({'error': 'Question not found'}), 404
    feedbacks = Feedback.query.filter_by(question_id=question_id).all()
    if not feedbacks:
        return jsonify({'message': 'No feedback available for this question'}), 404
    feedback_data = [{"user_id": f.user_id, "comment": f.comment, "date": f.created_at.strftime("%Y-%m-%d %H:%M:%S")} for f in feedbacks]
    return jsonify({"question": question.question, "feedback": feedback_data})

@app.route('/trivia/feedback/all', methods=['GET'])
def get_all_feedback():
    feedbacks = Feedback.query.all()
    if not feedbacks:
        return jsonify({'message': 'No feedback available'}), 404
    feedback_data = [{
        "id": fb.id,
        "user_id": fb.user_id,
        "question_id": fb.question_id,
        "comment": fb.comment,
        "date": fb.created_at.strftime("%Y-%m-%d %H:%M:%S") if fb.created_at else None
    } for fb in feedbacks]
    return jsonify({"feedback": feedback_data})

@app.route('/trivia/feedback/<int:feedback_id>', methods=['DELETE'])
@jwt_required()
def delete_feedback(feedback_id):
    user_id = int(get_jwt_identity())  
    feedback = Feedback.query.get(feedback_id)
    if not feedback:
        return jsonify({'error': 'Feedback not found'}), 404
    if feedback.user_id != user_id:
        return jsonify({'error': 'Unauthorized: You can only delete your own feedback'}), 403
    db.session.delete(feedback)
    db.session.commit()
    return jsonify({'message': f'Feedback {feedback_id} deleted successfully'})

# -------------------- Notification Endpoints --------------------

@app.route('/trivia/notifications', methods=['POST'])
@jwt_required()
def add_notification():
    data = request.json
    user_id = get_jwt_identity()
    message = data.get('message')
    if not message:
        return jsonify({'error': 'Notification message is required'}), 400
    notification = Notification(user_id=user_id, message=message)
    db.session.add(notification)
    db.session.commit()
    return jsonify({'message': 'Notification added successfully'}), 201

@app.route('/trivia/notifications', methods=['GET'])
@jwt_required()
def get_notifications():
    user_id = get_jwt_identity()
    notifications = Notification.query.filter_by(user_id=user_id).all()
    if not notifications:
        return jsonify({'message': 'No notifications found'}), 404
    return jsonify({
        "notifications": [
            {
                "id": n.id,
                "message": n.message,
                "date": n.created_at.strftime("%Y-%m-%d %H:%M:%S")
            } for n in notifications
        ]
    })

@app.route('/trivia/notifications', methods=['DELETE'])
@jwt_required()
def delete_notifications():
    user_id = get_jwt_identity()
    notifications = Notification.query.filter_by(user_id=user_id).all()
    if not notifications:
        return jsonify({'message': 'No notifications to delete'}), 404
    for notif in notifications:
        db.session.delete(notif)
    db.session.commit()
    return jsonify({'message': 'All notifications deleted successfully'})

@app.route('/trivia/notifications/<int:notification_id>', methods=['DELETE'])
@jwt_required()
def delete_notification_by_id(notification_id):
    user_id = get_jwt_identity()
    notification = Notification.query.filter_by(id=notification_id, user_id=user_id).first()
    if not notification:
        return jsonify({'error': 'Notification not found'}), 404
    db.session.delete(notification)
    db.session.commit()
    return jsonify({'message': f'Notification {notification_id} deleted successfully'})

if __name__ == '__main__':
    app.run(debug=True)
