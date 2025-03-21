import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SQLALCHEMY_DATABASE_URI = 'sqlite:///trivia.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = 'c20573afea2628363dde7783687821c082a492ac3e83e4bb20bd7d868a2d8583' 
    JWT_SECRET_KEY = '96ed92cc061295ff35519dce86fb5ada297d89ebd00509934e57f976af9cb3ca'  
    