# Trivia Quiz API

A RESTful API for a trivia quiz game built with Flask. Users can register, log in, take quiz sessions of up to 10 questions, get hints and explanations, track their scores, and compete on a leaderboard. The API also supports question management, tagging, user feedback, and notifications when new questions are added.

## Features

- **User accounts** with registration, login, logout, and account deletion. Passwords are hashed with bcrypt and routes are protected with JWT, including token blacklisting on logout.
- **Question management** to add, view, update, and delete trivia questions, each with a category, difficulty, answer, explanation, and tags.
- **Quiz sessions** that pull up to 10 random questions, accept answers, and compute the score. A bonus point is awarded for high-scoring sessions.
- **Hints and explanations** that give the word count plus first and last letters of the answer, and an explanation after answering.
- **Flexible answer checking** that ignores letter case and extra spaces.
- **Filtering** by category, difficulty, and random selection, plus question counts per category.
- **Scores, history, and leaderboard** showing each user's past sessions and the top 10 players.
- **Recommendations** of categories based on the user's past quiz performance, and a list of similar questions.
- **Feedback** so users can comment on questions.
- **Notifications** that alert users when new questions are added to a category they follow.

## Tech Stack

- Python 3.11
- Flask
- Flask-SQLAlchemy and SQLite
- Flask-Migrate (Alembic)
- Flask-JWT-Extended
- Flask-Bcrypt

## Project Structure

```
trivia-quiz/
├── routes.py        Main app and all trivia endpoints
├── auth.py          Register, login, logout, and delete account
├── models.py        Database models
├── database.py      SQLAlchemy setup
├── config.py        App configuration
├── migrations/      Database migration files
└── requirements.txt
```

## Getting Started

1. Clone the repository.
   ```bash
   git clone https://github.com/esir-ops/trivia-quiz.git
   cd trivia-quiz
   ```
2. Create and activate a virtual environment.
   ```bash
   python -m venv venv
   venv\Scripts\activate        # Windows
   source venv/bin/activate     # macOS / Linux
   ```
3. Install the dependencies.
   ```bash
   pip install -r requirements.txt
   ```
4. Apply the database migrations.
   ```bash
   flask --app routes db upgrade
   ```
5. Run the server.
   ```bash
   python routes.py
   ```
   The API runs at `http://127.0.0.1:5000`.

## API Endpoints

Endpoints marked with 🔒 need a JWT token in the header: `Authorization: Bearer <token>`.

### Authentication

| Method | Endpoint | Description |
|---|---|---|
| POST | `/auth/register` | Create an account |
| POST | `/auth/login` | Log in and get a token |
| POST | `/auth/logout` | 🔒 Log out and revoke the token |
| DELETE | `/auth/delete` | 🔒 Delete your account |

### Questions

| Method | Endpoint | Description |
|---|---|---|
| POST | `/trivia/questions` | Add a question |
| GET | `/trivia/questions` | List all questions |
| GET | `/trivia/questions/<id>` | Get a question |
| PUT | `/trivia/questions/<id>` | Update a question |
| DELETE | `/trivia/questions/<id>` | Delete a question |
| GET | `/trivia/categories` | List categories |
| GET | `/trivia/questions/random` | Get a random question |
| GET | `/trivia/questions/<category>/random` | Random question from a category |
| GET | `/trivia/questions/<category>/count` | Count questions in a category |
| GET | `/trivia/questions/<category>/<difficulty>` | Filter by category and difficulty |
| GET / PUT | `/trivia/questions/<id>/tags` | View or update tags |
| GET | `/trivia/questions/<id>/hints` | Get a hint |
| POST | `/trivia/questions/<id>/answer` | Check an answer |
| GET / PUT | `/trivia/questions/<id>/explanation` | View or update the explanation |
| GET | `/trivia/questions/similar/<id>` | Get similar questions |
| GET | `/trivia/questions/quiz` | Generate a practice quiz set |

### Quiz, Scores, and Leaderboard

| Method | Endpoint | Description |
|---|---|---|
| POST | `/trivia/quiz/start` | 🔒 Start a quiz (max 10 questions) |
| POST | `/trivia/quiz/answer` | 🔒 Submit answers |
| POST | `/trivia/quiz/end` | 🔒 End the quiz |
| PUT | `/trivia/score/update` | 🔒 Apply the session bonus |
| GET | `/trivia/score/<user_id>` | 🔒 View score history |
| GET | `/trivia/user/<user_id>/history` | 🔒 View quiz history |
| GET | `/trivia/quiz/recommendations` | 🔒 Get category recommendations |
| GET | `/trivia/leaderboard` | Top 10 players |

### Feedback and Notifications

| Method | Endpoint | Description |
|---|---|---|
| POST | `/trivia/feedback` | 🔒 Submit feedback on a question |
| GET | `/trivia/feedback/<question_id>` | View feedback for a question |
| GET | `/trivia/feedback/all` | View all feedback |
| DELETE | `/trivia/feedback/<id>` | 🔒 Delete feedback |
| POST / GET / DELETE | `/trivia/notifications` | 🔒 Add, view, or clear notifications |
| DELETE | `/trivia/notifications/<id>` | 🔒 Delete one notification |

## Sample Request

**Login**
```http
POST /auth/login
Content-Type: application/json

{
  "username": "player1",
  "password": "mypassword"
}
```

**Response**
```json
{
  "message": "Login successful",
  "access_token": "<your-token>",
  "user_id": 1,
  "notifications": []
}
```

## Author

Resi Ella R. Sicat
BS Computer Engineering, Holy Angel University
