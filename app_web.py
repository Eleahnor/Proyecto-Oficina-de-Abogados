"""
Estructura para implementación web futura usando Flask
"""

from flask import Flask, render_template, request, jsonify, session
from key_exchange_core import KeyExchangeSystem
import json

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Cambiar en producción

# En una implementación real, usarías una base de datos
users_systems = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/generate-keys', methods=['POST'])
def generate_keys():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Usuario no autenticado'}), 401
    
    system = users_systems.get(user_id, KeyExchangeSystem())
    system.generate_key_pair()
    users_systems[user_id] = system
    
    return jsonify({
        'success': True,
        'public_key': system.get_public_key_pem()
    })

@app.route('/api/add-member', methods=['POST'])
def add_member():
    user_id = session.get('user_id')
    if not user_id or user_id not in users_systems:
        return jsonify({'error': 'Usuario no autenticado'}), 401
    
    data = request.get_json()
    member_id = data.get('member_id')
    public_key_pem = data.get('public_key')
    
    if not member_id or not public_key_pem:
        return jsonify({'error': 'Datos incompletos'}), 400
    
    system = users_systems[user_id]
    success = system.add_team_member_public_key(member_id, public_key_pem)
    
    return jsonify({'success': success})

@app.route('/api/generate-symmetric-key', methods=['POST'])
def generate_symmetric_key():
    user_id = session.get('user_id')
    if not user_id or user_id not in users_systems:
        return jsonify({'error': 'Usuario no autenticado'}), 401
    
    data = request.get_json()
    key_name = data.get('key_name', 'default')
    
    system = users_systems[user_id]
    symmetric_key = system.generate_symmetric_key()
    
    # Encriptar para cada miembro
    encrypted_keys = {}
    for member_id in system.team_public_keys.keys():
        try:
            encrypted_key = system.encrypt_symmetric_key(member_id, symmetric_key)
            encrypted_keys[member_id] = encrypted_key
        except Exception as e:
            encrypted_keys[member_id] = f"Error: {str(e)}"
    
    system.symmetric_keys[key_name] = symmetric_key.hex()
    
    return jsonify({
        'success': True,
        'encrypted_keys': encrypted_keys,
        'symmetric_key': symmetric_key.hex()
    })

@app.route('/api/my-keys')
def get_my_keys():
    user_id = session.get('user_id')
    if not user_id or user_id not in users_systems:
        return jsonify({'error': 'Usuario no autenticado'}), 401
    
    system = users_systems[user_id]
    
    return jsonify({
        'public_key': system.get_public_key_pem(),
        'team_members': list(system.team_public_keys.keys()),
        'symmetric_keys': system.symmetric_keys
    })

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user_id = data.get('user_id')
    
    if user_id:
        session['user_id'] = user_id
        if user_id not in users_systems:
            users_systems[user_id] = KeyExchangeSystem()
        return jsonify({'success': True})
    
    return jsonify({'success': False})

if __name__ == '__main__':
    app.run(debug=True)