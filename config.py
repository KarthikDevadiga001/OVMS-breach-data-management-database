import os

class Config:
    SECRET_KEY = 'your-secret-key'
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:your_password@localhost:5432/OVMS'
    SQLALCHEMY_TRACK_MODIFICATIONS = False


