# app.py - Backend en la nube (solo autenticación)
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from models import db, User

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Usa PostgreSQL en producción
app.config['JWT_SECRET_KEY'] = 'tu_clave_jwt_muy_segura_y_unica'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
CORS(app)
JWTManager(app)

@app.before_first_request
def create_tables():
    db.create_all()

# Registro
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Usuario ya existe'}), 400
    if data['role'] not in User.ROLES:
        return jsonify({'error': 'Rol no válido'}), 400

    user = User(username=data['username'], role=data['role'])
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
        return jsonify({'token': user.get_token(), 'role': user.role}), 200
    return jsonify({'error': 'Credenciales inválidas'}), 401

# Perfil (opcional)
@app.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    current_user = get_jwt_identity()
    return jsonify({'user': current_user})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.getenv('PORT', 5000)))