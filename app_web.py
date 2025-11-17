from flask import Flask, render_template, request, jsonify, session
from key_exchange_core import KeyExchangeSystem
import json
import os

app = Flask(__name__)
app.secret_key = 'clave-secreta-para-sesiones'  # En producción usa una clave segura

# Almacenamiento en memoria (en producción usarías una base de datos)
users_systems = {}

def get_user_system():
    """Obtiene el sistema de llaves del usuario actual"""
    user_id = session.get('user_id')
    if not user_id:
        return None
    
    if user_id not in users_systems:
        users_systems[user_id] = KeyExchangeSystem()
    
    return users_systems[user_id]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user_id = data.get('user_id')
    
    if user_id:
        session['user_id'] = user_id
        return jsonify({'success': True, 'message': f'Bienvenido {user_id}'})
    
    return jsonify({'success': False, 'error': 'ID de usuario requerido'})

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'success': True, 'message': 'Sesión cerrada'})

@app.route('/api/generate-keys', methods=['POST'])
def generate_keys():
    system = get_user_system()
    if not system:
        return jsonify({'error': 'Usuario no autenticado'}), 401
    
    system.generate_key_pair()
    
    return jsonify({
        'success': True,
        'message': 'Llaves generadas exitosamente',
        'public_key': system.get_public_key_pem()
    })

@app.route('/api/add-member', methods=['POST'])
def add_member():
    system = get_user_system()
    if not system:
        return jsonify({'error': 'Usuario no autenticado'}), 401
    
    data = request.get_json()
    member_id = data.get('member_id')
    public_key_pem = data.get('public_key')
    
    if not member_id or not public_key_pem:
        return jsonify({'error': 'ID del miembro y llave pública son requeridos'}), 400
    
    success = system.add_team_member_public_key(member_id, public_key_pem)
    
    if success:
        return jsonify({
            'success': True,
            'message': f'Miembro {member_id} agregado exitosamente'
        })
    else:
        return jsonify({'error': 'Error al agregar la llave pública'}), 400

@app.route('/api/generate-symmetric-key', methods=['POST'])
def generate_symmetric_key():
    system = get_user_system()
    if not system:
        return jsonify({'error': 'Usuario no autenticado'}), 401
    
    data = request.get_json()
    key_name = data.get('key_name', 'default')
    
    if not system.team_public_keys:
        return jsonify({'error': 'No hay miembros en el equipo'}), 400
    
    symmetric_key = system.generate_symmetric_key()
    
    # Encriptar para cada miembro
    encrypted_keys = {}
    for member_id in system.team_public_keys.keys():
        try:
            encrypted_key = system.encrypt_symmetric_key(member_id, symmetric_key)
            encrypted_keys[member_id] = encrypted_key
        except Exception as e:
            encrypted_keys[member_id] = f"Error: {str(e)}"
    
    # Guardar la llave simétrica
    import base64
    system.symmetric_keys[key_name] = base64.b64encode(symmetric_key).decode('utf-8')
    
    return jsonify({
        'success': True,
        'message': f'Llave simétrica "{key_name}" generada y encriptada',
        'encrypted_keys': encrypted_keys,
        'symmetric_key_hex': symmetric_key.hex()
    })

@app.route('/api/my-keys', methods=['GET'])
def get_my_keys():
    system = get_user_system()
    if not system:
        return jsonify({'error': 'Usuario no autenticado'}), 401
    
    return jsonify({
        'public_key': system.get_public_key_pem(),
        'team_members': list(system.team_public_keys.keys()),
        'symmetric_keys': system.symmetric_keys
    })

@app.route('/api/save-keys', methods=['POST'])
def save_keys():
    system = get_user_system()
    if not system:
        return jsonify({'error': 'Usuario no autenticado'}), 401
    
    filename = f"keys_{session['user_id']}.json"
    system.save_keys_to_file(filename)
    
    return jsonify({
        'success': True,
        'message': f'Llaves guardadas en {filename}'
    })

@app.route('/api/load-keys', methods=['POST'])
def load_keys():
    system = get_user_system()
    if not system:
        return jsonify({'error': 'Usuario no autenticado'}), 401
    
    filename = f"keys_{session['user_id']}.json"
    success = system.load_keys_from_file(filename)
    
    if success:
        return jsonify({
            'success': True,
            'message': f'Llaves cargadas desde {filename}'
        })
    else:
        return jsonify({'error': 'Archivo no encontrado'}), 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)