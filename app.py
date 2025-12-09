from flask import Flask, render_template, request, jsonify, session, send_file, redirect, url_for
from werkzeug.utils import secure_filename
import os
import json
import secrets
from functools import wraps
from datetime import timedelta

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
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

# Crear directorios necesarios
for folder in ['uploads', 'keys', 'documents', 'signatures']:
    os.makedirs(folder, exist_ok=True)

# Configuración de equipos y usuarios
TEAMS_CONFIG = {
    "Pensión alimenticia": {
        "abogado": {"username": "Boloñesa", "password": "avril789", "role": "abogado"},
        "clientes": [
            {"username": "Ramírez", "password": "mar789", "role": "cliente"},
            {"username": "Hidalgo", "password": "daniel789", "role": "cliente"}
        ],
        "otro": {"username": "Mejía", "password": "avril123", "role": "otro"}
    },
    "Divorcio": {
        "abogado": {"username": "Cruz", "password": "daniel456", "role": "abogado"},
        "clientes": [
            {"username": "Pérez", "password": "mar456", "role": "cliente"},
            {"username": "Perejil", "password": "avril456", "role": "cliente"}
        ],
        "otro": {"username": "Estrada", "password": "daniel123", "role": "otro"}
    },
    "Asunto hipotecario": {
        "abogado": {"username": "Castro", "password": "mar123", "role": "abogado"},
        "clientes": [
            {"username": "Pérez", "password": "mar456", "role": "cliente"}
        ],
        "otro": {"username": "Estrada", "password": "daniel123", "role": "otro"}
    }
}

# Crear índice de usuarios para login rápido
USERS_INDEX = {}
for team_name, team_data in TEAMS_CONFIG.items():
    abogado = team_data["abogado"]
    USERS_INDEX[abogado["username"]] = {
        **abogado,
        "team": team_name
    }
    
    for cliente in team_data["clientes"]:
        if cliente["username"] not in USERS_INDEX:
            USERS_INDEX[cliente["username"]] = {
                **cliente,
                "team": team_name
            }
        else:
            # Usuario en múltiples equipos
            if isinstance(USERS_INDEX[cliente["username"]]["team"], list):
                USERS_INDEX[cliente["username"]]["team"].append(team_name)
            else:
                USERS_INDEX[cliente["username"]]["team"] = [
                    USERS_INDEX[cliente["username"]]["team"],
                    team_name
                ]
    
    otro = team_data["otro"]
    if otro["username"] not in USERS_INDEX:
        USERS_INDEX[otro["username"]] = {
            **otro,
            "team": team_name
        }
    else:
        if isinstance(USERS_INDEX[otro["username"]]["team"], list):
            USERS_INDEX[otro["username"]]["team"].append(team_name)
        else:
            USERS_INDEX[otro["username"]]["team"] = [
                USERS_INDEX[otro["username"]]["team"],
                team_name
            ]

# Decorador para requerir login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({'success': False, 'error': 'Sesión no iniciada'}), 401
        return f(*args, **kwargs)
    return decorated_function

# Función auxiliar para obtener instancias del usuario
def get_user_instances(username):
    """Obtiene las instancias de KeyGenerator, Signer, etc. para el usuario"""
    key_gen = KeyGenerator(username)
    
    # Cargar llave privada si existe
    key_gen.load_private_key(username)
    
    # Cargar llaves públicas del equipo
    team_keys_file = f"keys/team_{session.get('current_team', '')}_public_keys.json"
    if os.path.exists(team_keys_file):
        key_gen.load_public_keys_from_file(team_keys_file)
    
    signer = DigitalSigner(key_gen)
    verifier = SignatureVerifier(key_gen)
    encryptor = DocumentEncryptor()
    decryptor = DocumentDecryptor()
    key_encryptor = KeyEncryptor()
    key_decryptor = KeyDecryptor()
    
    return {
        'key_gen': key_gen,
        'signer': signer,
        'verifier': verifier,
        'encryptor': encryptor,
        'decryptor': decryptor,
        'key_encryptor': key_encryptor,
        'key_decryptor': key_decryptor
    }

# ============= RUTAS DE AUTENTICACIÓN =============

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if username in USERS_INDEX and USERS_INDEX[username]['password'] == password:
        user_data = USERS_INDEX[username]
        session.permanent = True
        session['username'] = username
        session['role'] = user_data['role']
        
        # Manejar usuarios en múltiples equipos
        if isinstance(user_data['team'], list):
            session['teams'] = user_data['team']
            session['current_team'] = user_data['team'][0]  # Default al primer equipo
        else:
            session['current_team'] = user_data['team']
            session['teams'] = [user_data['team']]
        
        return jsonify({
            'success': True,
            'username': username,
            'role': user_data['role'],
            'team': session['current_team'],
            'teams': session['teams']
        })
    
    return jsonify({'success': False, 'error': 'Credenciales inválidas'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/switch_team', methods=['POST'])
@login_required
def switch_team():
    data = request.get_json()
    new_team = data.get('team')
    
    if new_team in session.get('teams', []):
        session['current_team'] = new_team
        return jsonify({'success': True, 'team': new_team})
    
    return jsonify({'success': False, 'error': 'Equipo no autorizado'}), 403

# ============= DASHBOARD =============

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/user_info')
@login_required
def user_info():
    team_members = get_team_members(session['current_team'])
    
    # Verificar si el usuario tiene llaves generadas
    private_key_exists = os.path.exists(f"keys/private_key_{session['username']}.pem")
    
    return jsonify({
        'username': session['username'],
        'role': session['role'],
        'team': session['current_team'],
        'teams': session.get('teams', [session['current_team']]),
        'team_members': team_members,
        'has_keys': private_key_exists
    })

def get_team_members(team_name):
    """Obtiene lista de miembros del equipo"""
    if team_name not in TEAMS_CONFIG:
        return []
    
    team_data = TEAMS_CONFIG[team_name]
    members = [team_data["abogado"]["username"]]
    members.extend([c["username"] for c in team_data["clientes"]])
    members.append(team_data["otro"]["username"])
    
    return list(set(members))  # Eliminar duplicados

# ============= GESTIÓN DE LLAVES =============

@app.route('/api/keys/generate', methods=['POST'])
@login_required
def generate_keys():
    username = session['username']
    instances = get_user_instances(username)
    key_gen = instances['key_gen']
    
    # Generar par de llaves
    public_key_pem = key_gen.generate_key_pair()
    
    # Guardar en directorio keys/
    private_file = f"keys/private_key_{username}.pem"
    public_file = f"keys/public_key_{username}.pem"
    
    # Mover archivos generados al directorio keys/
    if os.path.exists(f"private_key_{username}.pem"):
        os.rename(f"private_key_{username}.pem", private_file)
    if os.path.exists(f"public_key_{username}.pem"):
        os.rename(f"public_key_{username}.pem", public_file)
    
    # Registrar llave pública en el equipo
    team_keys_file = f"keys/team_{session['current_team']}_public_keys.json"
    key_gen.add_team_member_public_key(username, public_key_pem)
    key_gen.save_public_keys_to_file(team_keys_file)
    
    return jsonify({
        'success': True,
        'message': 'Llaves generadas exitosamente',
        'public_key': public_key_pem
    })

@app.route('/api/keys/download_private', methods=['GET'])
@login_required
def download_private_key():
    username = session['username']
    filepath = f"keys/private_key_{username}.pem"
    
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    
    return jsonify({'success': False, 'error': 'Llave no encontrada'}), 404

@app.route('/api/keys/team_members', methods=['GET'])
@login_required
def get_team_keys():
    team_name = session['current_team']
    team_keys_file = f"keys/team_{team_name}_public_keys.json"
    
    if os.path.exists(team_keys_file):
        with open(team_keys_file, 'r') as f:
            data = json.load(f)
        
        return jsonify({
            'success': True,
            'members': list(data.get('team_public_keys', {}).keys())
        })
    
    return jsonify({'success': True, 'members': []})

# ============= GESTIÓN DE DOCUMENTOS =============

@app.route('/api/documents/upload', methods=['POST'])
@login_required
def upload_document():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No se envió archivo'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'Nombre de archivo vacío'}), 400
    
    # Validar que sea PDF
    if not file.filename.lower().endswith('.pdf'):
        return jsonify({'success': False, 'error': 'Solo se permiten archivos PDF'}), 400
    
    filename = secure_filename(file.filename)
    team_folder = f"documents/{session['current_team']}"
    os.makedirs(team_folder, exist_ok=True)
    
    filepath = os.path.join(team_folder, filename)
    file.save(filepath)
    
    return jsonify({
        'success': True,
        'filename': filename,
        'path': filepath
    })

@app.route('/api/documents/list', methods=['GET'])
@login_required
def list_documents():
    team_folder = f"documents/{session['current_team']}"
    
    if not os.path.exists(team_folder):
        return jsonify({'success': True, 'documents': []})
    
    documents = []
    for filename in os.listdir(team_folder):
        filepath = os.path.join(team_folder, filename)
        
        # Determinar tipo de documento
        doc_type = 'unknown'
        if filename.endswith('.pdf'):
            doc_type = 'original'
        elif filename.endswith('.enc'):
            doc_type = 'encrypted'
        elif filename.endswith('.key'):
            doc_type = 'key'
        elif filename.endswith('.json'):
            doc_type = 'signature'
        
        documents.append({
            'filename': filename,
            'type': doc_type,
            'size': os.path.getsize(filepath),
            'path': filepath
        })
    
    return jsonify({'success': True, 'documents': documents})

@app.route('/api/documents/download/<path:filename>', methods=['GET'])
@login_required
def download_document(filename):
    team_folder = f"documents/{session['current_team']}"
    filepath = os.path.join(team_folder, secure_filename(filename))
    
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    
    return jsonify({'success': False, 'error': 'Documento no encontrado'}), 404

# ============= CIFRADO DE DOCUMENTOS =============

@app.route('/api/encrypt/generate_aes', methods=['POST'])
@login_required
def generate_aes_key():
    """Genera llave AES y la devuelve en base64"""
    instances = get_user_instances(session['username'])
    encryptor = instances['encryptor']
    
    aes_key = encryptor.generar_clave_aes()
    
    return jsonify({
        'success': True,
        'aes_key': aes_key.decode('utf-8')
    })

@app.route('/api/encrypt/document', methods=['POST'])
@login_required
def encrypt_document():
    data = request.get_json()
    filename = data.get('filename')
    aes_key_b64 = data.get('aes_key')
    
    team_folder = f"documents/{session['current_team']}"
    filepath = os.path.join(team_folder, secure_filename(filename))
    
    if not os.path.exists(filepath):
        return jsonify({'success': False, 'error': 'Documento no encontrado'}), 404
    
    instances = get_user_instances(session['username'])
    encryptor = instances['encryptor']
    
    # Convertir llave de base64
    aes_key = aes_key_b64.encode('utf-8')
    
    # Guardar llave temporalmente
    key_file = os.path.join(team_folder, f"key_{filename}.key")
    with open(key_file, 'wb') as f:
        f.write(aes_key)
    
    # Cifrar documento
    encrypted_file = os.path.join(team_folder, f"encrypted_{filename}.enc")
    
    if encryptor.cifrar_archivo(filepath, encrypted_file, aes_key):
        return jsonify({
            'success': True,
            'encrypted_file': f"encrypted_{filename}.enc",
            'key_file': f"key_{filename}.key"
        })
    
    return jsonify({'success': False, 'error': 'Error al cifrar'}), 500

@app.route('/api/encrypt/wrap_key', methods=['POST'])
@login_required
def wrap_aes_key():
    """Cifra llave AES para un miembro del equipo"""
    data = request.get_json()
    key_filename = data.get('key_filename')
    recipient = data.get('recipient')
    
    team_folder = f"documents/{session['current_team']}"
    key_path = os.path.join(team_folder, secure_filename(key_filename))
    recipient_public_key = f"keys/public_key_{recipient}.pem"
    
    if not os.path.exists(key_path):
        return jsonify({'success': False, 'error': 'Llave AES no encontrada'}), 404
    
    if not os.path.exists(recipient_public_key):
        return jsonify({'success': False, 'error': f'Llave pública de {recipient} no encontrada'}), 404
    
    instances = get_user_instances(session['username'])
    key_encryptor = instances['key_encryptor']
    
    result = key_encryptor.encrypt_aes_key_for_recipient(key_path, recipient_public_key)
    
    if result['success']:
        # Mover archivo cifrado al equipo con nombre apropiado
        wrapped_filename = f"wrapped_key_for_{recipient}.enc"
        wrapped_path = os.path.join(team_folder, wrapped_filename)
        
        if os.path.exists(result['encrypted_file']):
            os.rename(result['encrypted_file'], wrapped_path)
        
        return jsonify({
            'success': True,
            'wrapped_file': wrapped_filename,
            'recipient': recipient
        })
    
    return jsonify(result), 500

@app.route('/api/decrypt/unwrap_key', methods=['POST'])
@login_required
def unwrap_aes_key():
    """Descifra llave AES envuelta"""
    data = request.get_json()
    wrapped_filename = data.get('wrapped_filename')
    
    team_folder = f"documents/{session['current_team']}"
    wrapped_path = os.path.join(team_folder, secure_filename(wrapped_filename))
    my_private_key = f"keys/private_key_{session['username']}.pem"
    
    if not os.path.exists(wrapped_path):
        return jsonify({'success': False, 'error': 'Llave cifrada no encontrada'}), 404
    
    instances = get_user_instances(session['username'])
    key_decryptor = instances['key_decryptor']
    
    result = key_decryptor.decrypt_aes_key_with_private(wrapped_path, my_private_key)
    
    if result['success']:
        # Mover llave recuperada al equipo
        recovered_filename = f"recovered_key_{session['username']}.key"
        recovered_path = os.path.join(team_folder, recovered_filename)
        
        if os.path.exists(result['decrypted_file']):
            os.rename(result['decrypted_file'], recovered_path)
        
        return jsonify({
            'success': True,
            'key_file': recovered_filename
        })
    
    return jsonify(result), 500

@app.route('/api/decrypt/document', methods=['POST'])
@login_required
def decrypt_document():
    data = request.get_json()
    encrypted_filename = data.get('encrypted_filename')
    key_filename = data.get('key_filename')
    
    team_folder = f"documents/{session['current_team']}"
    encrypted_path = os.path.join(team_folder, secure_filename(encrypted_filename))
    key_path = os.path.join(team_folder, secure_filename(key_filename))
    
    if not os.path.exists(encrypted_path) or not os.path.exists(key_path):
        return jsonify({'success': False, 'error': 'Archivos no encontrados'}), 404
    
    instances = get_user_instances(session['username'])
    decryptor = instances['decryptor']
    
    result = decryptor.decrypt_with_keyfile(encrypted_path, key_path)
    
    if result['success']:
        # Mover archivo descifrado al equipo
        decrypted_filename = os.path.basename(result['decrypted_path'])
        final_path = os.path.join(team_folder, decrypted_filename)
        
        if os.path.exists(result['decrypted_path']) and result['decrypted_path'] != final_path:
            os.rename(result['decrypted_path'], final_path)
        
        return jsonify({
            'success': True,
            'decrypted_file': decrypted_filename
        })
    
    return jsonify(result), 500

# ============= FIRMAS DIGITALES =============

@app.route('/api/sign/document', methods=['POST'])
@login_required
def sign_document():
    data = request.get_json()
    filename = data.get('filename')
    
    team_folder = f"documents/{session['current_team']}"
    filepath = os.path.join(team_folder, secure_filename(filename))
    
    if not os.path.exists(filepath):
        return jsonify({'success': False, 'error': 'Documento no encontrado'}), 404
    
    instances = get_user_instances(session['username'])
    signer = instances['signer']
    
    if not instances['key_gen'].private_key:
        return jsonify({'success': False, 'error': 'Debe generar llaves primero'}), 400
    
    signature_package = signer.sign_document(filepath)
    
    # Guardar firma
    sig_filename = f"firma_{session['username']}_{filename}.json"
    sig_path = os.path.join(team_folder, sig_filename)
    
    with open(sig_path, 'w') as f:
        json.dump(signature_package, f, indent=2)
    
    return jsonify({
        'success': True,
        'signature_file': sig_filename,
        'document_hash': signature_package['document_hash']
    })

@app.route('/api/verify/signature', methods=['POST'])
@login_required
def verify_signature():
    data = request.get_json()
    filename = data.get('filename')
    signature_files = data.get('signature_files', [])
    
    team_folder = f"documents/{session['current_team']}"
    filepath = os.path.join(team_folder, secure_filename(filename))
    
    if not os.path.exists(filepath):
        return jsonify({'success': False, 'error': 'Documento no encontrado'}), 404
    
    instances = get_user_instances(session['username'])
    verifier = instances['verifier']
    
    results = []
    for sig_file in signature_files:
        sig_path = os.path.join(team_folder, secure_filename(sig_file))
        
        if not os.path.exists(sig_path):
            results.append({
                'file': sig_file,
                'valid': False,
                'error': 'Archivo de firma no encontrado'
            })
            continue
        
        try:
            with open(sig_path, 'r') as f:
                signature_package = json.load(f)
            
            valid = verifier.verify_signature(signature_package, filepath)
            
            results.append({
                'file': sig_file,
                'user': signature_package.get('user_id'),
                'valid': valid,
                'hash': signature_package.get('document_hash')
            })
        except Exception as e:
            results.append({
                'file': sig_file,
                'valid': False,
                'error': str(e)
            })
    
    return jsonify({
        'success': True,
        'results': results
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
