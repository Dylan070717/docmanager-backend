# backend-cloud/app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)

# === Configuración desde variables de entorno ===
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///users.db')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'tu_clave_jwt_muy_segura')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# === Inicializar extensiones ===
db = SQLAlchemy(app)
CORS(app, supports_credentials=True)  # Importante para cookies/tokens
JWTManager(app)

# === Modelos ===
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='user')

    def set_password(self, password):
        from werkzeug.security import generate_password_hash
        self.password = generate_password_hash(password)

    def check_password(self, password):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password, password)

# === Rutas ===

# Registro
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Usuario ya existe'}), 400
    user = User(username=data['username'], role=data.get('role', 'user'))
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    return jsonify({'msg': 'Usuario registrado'}), 201

# Login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and user.check_password(data['password']):
        token = create_access_token(identity={'id': user.id, 'role': user.role})
        return jsonify({'token': token, 'role': user.role}), 200
    return jsonify({'error': 'Credenciales inválidas'}), 401

# Perfil (ruta protegida)
@app.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    current_user = get_jwt_identity()
    return jsonify({'user': current_user})

# Ruta de prueba (opcional)
@app.route('/test', methods=['GET'])
@jwt_required()
def test():
    return jsonify({'msg': 'Acceso permitido con token'})

# === Inicializar base de datos ===
@app.before_first_request
def create_tables():
    db.create_all()

if __name__ == '__main__':
    app.run(port=int(os.getenv('PORT', 5000)), host='0.0.0.0')