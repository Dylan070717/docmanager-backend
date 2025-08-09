# models.py
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import pbkdf2_sha256
from flask_jwt_extended import create_access_token

db = SQLAlchemy()

ROLES = ['admin', 'editor', 'viewer', 'user']

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='user')

    def set_password(self, password):
        self.password_hash = pbkdf2_sha256.hash(password)

    def check_password(self, password):
        return pbkdf2_sha256.verify(password, self.password_hash)

    def get_token(self):
        return create_access_token(identity={'id': self.id, 'username': self.username, 'role': self.role})