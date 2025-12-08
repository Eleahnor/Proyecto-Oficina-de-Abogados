from flask import Flask, request, jsonify, session, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
import json
import hashlib
import base64
import secrets
from datetime import datetime, timedelta
from functools import wraps

# Importar módulos existentes
from sign.digital_signer import DigitalSigner
from sign.signature_verifier import SignatureVerifier
from sign.key_generator import KeyGenerator
from cipher.Cifrado_doc import DocumentEncryptor
from cipher.Descifrado_doc import DocumentDecryptor
from cipher.cifradollave import KeyEncryptor
from cipher.decifradollave import KeyDecryptor

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

CORS(app)

# Crear carpetas necesarias
for folder in ['uploads', 'encrypted', 'signatures', 'data']:
    os.makedirs(folder, exist_ok=True)

# Archivo de usuarios
USERS_FILE = 'data/usuarios.json'
GROUPS_FILE = 'data/grupos.json'

# Diccionario para sistemas de usuario
user_systems = {}

# ============================================================================
# GESTIÓN DE USUARIOS Y GRUPOS
# ============================================================================

def init_users_file():
    """Inicializa el archivo de usuarios con usuarios por defecto"""
    if not os.path.exists(USERS_FILE):
        default_users = {
            "Director": {
                "password_hash": hashlib.sha256("director123".encode()).hexdigest(),
                "role": "director",
                "email": "director@legal.com",
                "created_at": datetime.now().isoformat()
            },
            "Abogado1": {
                "password_hash": hashlib.sha256("abogado123".encode()).hexdigest(),
                "role": "abogado",
                "email": "abogado1@legal.com",
                "created_at": datetime.now().isoformat()
            },
            "Abogado2": {
                "password_hash": hashlib.sha256("abogado123".encode()).hexdigest(),
                "role": "abogado",
                "email": "abogado2@legal.com",
                "created_at": datetime.now().isoformat()
            }
        }
        with open(USERS_FILE, 'w') as f:
            json.dump(default_users, f, indent=2)
        print("✅ Archivo de usuarios creado con usuarios por defecto")
        print("   Director: director123")
        print("   Abogado1: abogado123")
        print("   Abogado2: abogado123")

def init_groups_file():
    """Inicializa el archivo de grupos"""
    if not os.path.exists(GROUPS_FILE):
        with open(GROUPS_FILE, 'w') as f:
            json.dump({}, f, indent=2)

def load_users():
    """Carga usuarios desde archivo"""
    try:
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_users(users):
    """Guarda usuarios en archivo"""
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def load_groups():
    """Carga grupos desde archivo"""
    try:
        with open(GROUPS_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_groups(groups):
    """Guarda grupos en archivo"""
    with open(GROUPS_FILE, 'w') as f:
        json.dump(groups, f, indent=2)

def get_user_system(user_id):
    """Obtener o crear sistema para un usuario"""
    if user_id not in user_systems:
        key_gen = KeyGenerator()
        key_gen.user_id = user_id
        
        if os.path.exists("team_public_keys.json"):
            key_gen.load_public_keys_from_file("team_public_keys.json")
        
        key_gen.load_private_key(user_id)
        
        user_systems[user_id] = {
            'key_gen': key_gen,
            'signer': DigitalSigner(key_gen),
            'verifier': SignatureVerifier(key_gen),
            'encryptor': DocumentEncryptor(),
            'decryptor': DocumentDecryptor(),
            'key_encryptor': KeyEncryptor(),
            'key_decryptor': KeyDecryptor()
        }
    
    return user_systems[user_id]

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'No autenticado'}), 401
        return f(*args, **kwargs)
    return decorated_function

def director_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'No autenticado'}), 401
        
        users = load_users()
        user = users.get(session['user_id'])
        if not user or user.get('role') != 'director':
            return jsonify({'error': 'Acceso denegado - Solo directores'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

# ============================================================================
# AUTENTICACIÓN
# ============================================================================

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Login con validación de usuario y contraseña"""
    data = request.json
    user_id = data.get('user_id')
    password = data.get('password')
    
    if not user_id or not password:
        return jsonify({'error': 'Usuario y contraseña requeridos'}), 400
    
    users = load_users()
    user = users.get(user_id)
    
    if not user:
        return jsonify({'error': 'Usuario no encontrado'}), 401
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if password_hash != user['password_hash']:
        return jsonify({'error': 'Contraseña incorrecta'}), 401
    
    session['user_id'] = user_id
    session['role'] = user.get('role', 'abogado')
    session.permanent = True
    
    # Actualizar último login
    user['last_login'] = datetime.now().isoformat()
    save_users(users)
    
    system = get_user_system(user_id)
    
    return jsonify({
        'success': True,
        'user_id': user_id,
        'role': user.get('role'),
        'has_private_key': system['key_gen'].private_key is not None,
        'has_public_key': system['key_gen'].public_key is not None,
        'team_members': len(system['key_gen'].team_public_keys)
    })

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    if 'user_id' not in session:
        return jsonify({'authenticated': False})
    
    user_id = session['user_id']
    system = get_user_system(user_id)
    
    return jsonify({
        'authenticated': True,
        'user_id': user_id,
        'role': session.get('role', 'abogado'),
        'has_private_key': system['key_gen'].private_key is not None,
        'has_public_key': system['key_gen'].public_key is not None,
        'team_members': len(system['key_gen'].team_public_keys)
    })

# ============================================================================
# GESTIÓN DE USUARIOS (Solo Director)
# ============================================================================

@app.route('/api/users/list', methods=['GET'])
@login_required
def list_users():
    """Listar todos los usuarios"""
    users = load_users()
    user_list = []
    
    for user_id, user_data in users.items():
        user_list.append({
            'user_id': user_id,
            'role': user_data.get('role', 'abogado'),
            'email': user_data.get('email', ''),
            'created_at': user_data.get('created_at', ''),
            'has_keys': os.path.exists(f'private_key_{user_id}.pem')
        })
    
    return jsonify({'users': user_list})

@app.route('/api/users/create', methods=['POST'])
@director_required
def create_user():
    """Crear nuevo usuario (solo director)"""
    data = request.json
    user_id = data.get('user_id')
    password = data.get('password')
    role = data.get('role', 'abogado')
    email = data.get('email', '')
    
    if not user_id or not password:
        return jsonify({'error': 'Usuario y contraseña requeridos'}), 400
    
    users = load_users()
    
    if user_id in users:
        return jsonify({'error': 'El usuario ya existe'}), 400
    
    users[user_id] = {
        'password_hash': hashlib.sha256(password.encode()).hexdigest(),
        'role': role,
        'email': email,
        'created_at': datetime.now().isoformat(),
        'created_by': session['user_id']
    }
    
    save_users(users)
    
    return jsonify({
        'success': True,
        'message': f'Usuario {user_id} creado exitosamente'
    })

@app.route('/api/users/delete/<user_id>', methods=['DELETE'])
@director_required
def delete_user(user_id):
    """Eliminar usuario (solo director)"""
    if user_id == session['user_id']:
        return jsonify({'error': 'No puedes eliminar tu propio usuario'}), 400
    
    users = load_users()
    
    if user_id not in users:
        return jsonify({'error': 'Usuario no encontrado'}), 404
    
    del users[user_id]
    save_users(users)
    
    return jsonify({
        'success': True,
        'message': f'Usuario {user_id} eliminado'
    })

# ============================================================================
# GESTIÓN DE GRUPOS (Solo Director)
# ============================================================================

@app.route('/api/groups/create', methods=['POST'])
@director_required
def create_group():
    """Crear grupo de usuarios"""
    data = request.json
    group_name = data.get('group_name')
    members = data.get('members', [])
    
    if not group_name:
        return jsonify({'error': 'Nombre de grupo requerido'}), 400
    
    groups = load_groups()
    
    if group_name in groups:
        return jsonify({'error': 'El grupo ya existe'}), 400
    
    groups[group_name] = {
        'members': members,
        'created_at': datetime.now().isoformat(),
        'created_by': session['user_id']
    }
    
    save_groups(groups)
    
    return jsonify({
        'success': True,
        'message': f'Grupo {group_name} creado con {len(members)} miembros'
    })

@app.route('/api/groups/list', methods=['GET'])
@login_required
def list_groups():
    """Listar grupos"""
    groups = load_groups()
    
    group_list = []
    for group_name, group_data in groups.items():
        group_list.append({
            'name': group_name,
            'members': group_data.get('members', []),
            'member_count': len(group_data.get('members', [])),
            'created_at': group_data.get('created_at', ''),
            'created_by': group_data.get('created_by', '')
        })
    
    return jsonify({'groups': group_list})

@app.route('/api/groups/<group_name>', methods=['GET'])
@login_required
def get_group(group_name):
    """Obtener detalles de un grupo"""
    groups = load_groups()
    
    if group_name not in groups:
        return jsonify({'error': 'Grupo no encontrado'}), 404
    
    group = groups[group_name]
    return jsonify({
        'name': group_name,
        'members': group.get('members', []),
        'created_at': group.get('created_at', ''),
        'created_by': group.get('created_by', '')
    })

@app.route('/api/groups/<group_name>/members', methods=['POST'])
@director_required
def add_group_member(group_name):
    """Agregar miembro a grupo"""
    data = request.json
    member_id = data.get('member_id')
    
    if not member_id:
        return jsonify({'error': 'member_id requerido'}), 400
    
    groups = load_groups()
    
    if group_name not in groups:
        return jsonify({'error': 'Grupo no encontrado'}), 404
    
    if member_id not in groups[group_name]['members']:
        groups[group_name]['members'].append(member_id)
        save_groups(groups)
    
    return jsonify({
        'success': True,
        'message': f'{member_id} agregado al grupo {group_name}'
    })

@app.route('/api/groups/<group_name>/members/<member_id>', methods=['DELETE'])
@director_required
def remove_group_member(group_name, member_id):
    """Remover miembro de grupo"""
    groups = load_groups()
    
    if group_name not in groups:
        return jsonify({'error': 'Grupo no encontrado'}), 404
    
    if member_id in groups[group_name]['members']:
        groups[group_name]['members'].remove(member_id)
        save_groups(groups)
    
    return jsonify({
        'success': True,
        'message': f'{member_id} removido del grupo {group_name}'
    })

@app.route('/api/groups/<group_name>', methods=['DELETE'])
@director_required
def delete_group(group_name):
    """Eliminar grupo"""
    groups = load_groups()
    
    if group_name not in groups:
        return jsonify({'error': 'Grupo no encontrado'}), 404
    
    del groups[group_name]
    save_groups(groups)
    
    return jsonify({
        'success': True,
        'message': f'Grupo {group_name} eliminado'
    })

# ============================================================================
# GESTIÓN DE LLAVES
# ============================================================================

@app.route('/api/keys/generate', methods=['POST'])
@login_required
def generate_keys():
    user_id = session['user_id']
    system = get_user_system(user_id)
    
    try:
        public_key_pem = system['key_gen'].generate_key_pair()
        system['key_gen'].add_team_member_public_key(user_id, public_key_pem)
        system['key_gen'].save_public_keys_to_file("team_public_keys.json")
        
        return jsonify({
            'success': True,
            'message': 'Llaves generadas exitosamente'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/keys/status', methods=['GET'])
@login_required
def keys_status():
    user_id = session['user_id']
    system = get_user_system(user_id)
    
    return jsonify({
        'user_id': user_id,
        'private_key_loaded': system['key_gen'].private_key is not None,
        'public_key_loaded': system['key_gen'].public_key is not None,
        'team_members': list(system['key_gen'].team_public_keys.keys())
    })

# ============================================================================
# GESTIÓN DE DOCUMENTOS CON CONTROL DE ACCESO
# ============================================================================

@app.route('/api/documents/upload', methods=['POST'])
@login_required
def upload_document():
    if 'file' not in request.files:
        return jsonify({'error': 'No se envió archivo'}), 400
    
    file = request.files['file']
    group_name = request.form.get('group_name', '')
    
    if file.filename == '':
        return jsonify({'error': 'Nombre de archivo vacío'}), 400
    
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    # Guardar metadata del documento
    metadata = {
        'filename': filename,
        'uploaded_by': session['user_id'],
        'uploaded_at': datetime.now().isoformat(),
        'group': group_name,
        'size': os.path.getsize(filepath)
    }
    
    metadata_file = filepath + '.metadata'
    with open(metadata_file, 'w') as f:
        json.dump(metadata, f, indent=2)
    
    return jsonify({
        'success': True,
        'filename': filename,
        'group': group_name
    })

@app.route('/api/documents/list', methods=['GET'])
@login_required
def list_documents():
    """Listar documentos según permisos del usuario"""
    user_id = session['user_id']
    user_role = session.get('role', 'abogado')
    groups = load_groups()
    
    # Obtener grupos del usuario
    user_groups = []
    for group_name, group_data in groups.items():
        if user_id in group_data.get('members', []):
            user_groups.append(group_name)
    
    documents = []
    
    if os.path.exists(app.config['UPLOAD_FOLDER']):
        for filename in os.listdir(app.config['UPLOAD_FOLDER']):
            if filename.endswith('.metadata'):
                continue
                
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if not os.path.isfile(filepath):
                continue
            
            # Cargar metadata
            metadata_file = filepath + '.metadata'
            doc_group = ''
            uploaded_by = ''
            
            if os.path.exists(metadata_file):
                try:
                    with open(metadata_file, 'r') as f:
                        metadata = json.load(f)
                        doc_group = metadata.get('group', '')
                        uploaded_by = metadata.get('uploaded_by', '')
                except:
                    pass
            
            # Control de acceso
            has_access = False
            if user_role == 'director':
                has_access = True
            elif not doc_group:  # Sin grupo = todos pueden ver
                has_access = True
            elif doc_group in user_groups:
                has_access = True
            
            if not has_access:
                continue
            
            sig_file = os.path.join('signatures', f'firma_{filename}.json')
            enc_file = filepath + '.enc'
            
            documents.append({
                'name': filename,
                'size': os.path.getsize(filepath),
                'path': filepath,
                'group': doc_group,
                'uploaded_by': uploaded_by,
                'has_signature': os.path.exists(sig_file),
                'is_encrypted': os.path.exists(enc_file),
                'modified': datetime.fromtimestamp(
                    os.path.getmtime(filepath)
                ).isoformat()
            })
    
    return jsonify({'documents': documents})

# ============================================================================
# CIFRADO CON CONTROL DE GRUPOS
# ============================================================================

@app.route('/api/password/generate', methods=['POST'])
@login_required
def generate_aes_password():
    try:
        aes_key = secrets.token_bytes(32)
        aes_key_b64 = base64.b64encode(aes_key).decode('utf-8')
        
        return jsonify({
            'success': True,
            'aes_key': aes_key_b64
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/password/encrypt-for-group', methods=['POST'])
@login_required
def encrypt_password_for_group():
    """Cifra contraseña para todos los miembros de un grupo"""
    data = request.json
    aes_password = data.get('aes_password')
    group_name = data.get('group_name')
    
    if not aes_password or not group_name:
        return jsonify({'error': 'Faltan parámetros'}), 400
    
    groups = load_groups()
    if group_name not in groups:
        return jsonify({'error': 'Grupo no encontrado'}), 404
    
    members = groups[group_name].get('members', [])
    
    if not members:
        return jsonify({'error': 'El grupo no tiene miembros'}), 400
    
    user_id = session['user_id']
    system = get_user_system(user_id)
    
    encrypted_files = []
    errors = []
    
    for member_id in members:
        try:
            temp_file = f'temp_password_{user_id}_{member_id}.txt'
            with open(temp_file, 'w') as f:
                f.write(aes_password)
            
            result = system['key_encryptor'].encrypt_key_for_member(
                temp_file,
                member_id,
                system['key_gen']
            )
            
            if os.path.exists(temp_file):
                os.remove(temp_file)
            
            if result['success']:
                encrypted_files.append({
                    'member': member_id,
                    'file': result['encrypted_file']
                })
            else:
                errors.append({
                    'member': member_id,
                    'error': result.get('error')
                })
        except Exception as e:
            errors.append({
                'member': member_id,
                'error': str(e)
            })
    
    return jsonify({
        'success': True,
        'encrypted_count': len(encrypted_files),
        'encrypted_files': encrypted_files,
        'errors': errors
    })

@app.route('/api/encrypt/document', methods=['POST'])
@login_required
def encrypt_document():
    user_id = session['user_id']
    system = get_user_system(user_id)
    
    data = request.json
    file_path = data.get('file_path')
    password = data.get('password')
    
    if not file_path or not os.path.exists(file_path):
        return jsonify({'error': 'Documento no encontrado'}), 404
    
    if not password:
        return jsonify({'error': 'Contraseña requerida'}), 400
    
    try:
        result = system['encryptor'].encrypt_document(file_path, password)
        
        if result['success']:
            return jsonify({
                'success': True,
                'encrypted_file': result['encrypted_path'],
                'metadata_file': result['metadata_path']
            })
        else:
            return jsonify({'error': result.get('error')}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/decrypt/document', methods=['POST'])
@login_required
def decrypt_document():
    user_id = session['user_id']
    system = get_user_system(user_id)
    
    data = request.json
    encrypted_file = data.get('encrypted_file')
    metadata_file = data.get('metadata_file')
    password = data.get('password')
    
    if not all([encrypted_file, metadata_file, password]):
        return jsonify({'error': 'Faltan parámetros'}), 400
    
    try:
        result = system['decryptor'].decrypt_document(
            encrypted_file, metadata_file, password
        )
        
        if result['success']:
            return jsonify({
                'success': True,
                'decrypted_file': result['decrypted_path']
            })
        else:
            return jsonify({'error': result.get('error')}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Continuar con las demás funciones del código original...
# (Firmas digitales, estadísticas, etc.)

if __name__ == '__main__':
    print("=" * 60)
    print("  SISTEMA CRIPTOGRÁFICO LEGAL")
    print("=" * 60)
    
    init_users_file()
    init_groups_file()
    
    print(f"Servidor: http://localhost:5000")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)
