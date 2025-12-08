from flask import Flask, request, jsonify, session, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
import json
import hashlib
import base64
from datetime import datetime, timedelta
from functools import wraps

# Importar tus módulos existentes
from sign.digital_signer import DigitalSigner
from sign.signature_verifier import SignatureVerifier
from sign.key_generator import KeyGenerator
from cipher.Cifrado_doc import DocumentEncryptor
from cipher.Descifrado_doc import DocumentDecryptor
from cipher.cifradollave import KeyEncryptor
from cipher.decifradollave import KeyDecryptor

app = Flask(__name__)
app.secret_key = 'tu-clave-secreta-super-segura-cambiar-en-produccion'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

# Habilitar CORS para desarrollo
CORS(app)

# Crear carpetas necesarias
os.makedirs('uploads', exist_ok=True)
os.makedirs('encrypted', exist_ok=True)
os.makedirs('signatures', exist_ok=True)

# Diccionario para almacenar instancias por usuario
user_systems = {}

def get_user_system(user_id):
    """Obtener o crear sistema para un usuario"""
    if user_id not in user_systems:
        key_gen = KeyGenerator()
        key_gen.user_id = user_id
        
        # Cargar configuración de equipo si existe
        if os.path.exists("team_public_keys.json"):
            key_gen.load_public_keys_from_file("team_public_keys.json")
        
        # Intentar cargar llave privada del usuario
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
    """Decorador para rutas que requieren autenticación"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'No autenticado'}), 401
        return f(*args, **kwargs)
    return decorated_function

# ============================================================================
# AUTENTICACIÓN
# ============================================================================

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Login simple - en producción usar autenticación real"""
    data = request.json
    user_id = data.get('user_id')
    
    if not user_id:
        return jsonify({'error': 'Usuario requerido'}), 400
    
    session['user_id'] = user_id
    session.permanent = True
    
    # Obtener o crear sistema para el usuario
    system = get_user_system(user_id)
    
    return jsonify({
        'success': True,
        'user_id': user_id,
        'has_private_key': system['key_gen'].private_key is not None,
        'has_public_key': system['key_gen'].public_key is not None,
        'team_members': len(system['key_gen'].team_public_keys)
    })

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """Cerrar sesión"""
    session.clear()
    return jsonify({'success': True})

@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    """Verificar estado de autenticación"""
    if 'user_id' not in session:
        return jsonify({'authenticated': False})
    
    user_id = session['user_id']
    system = get_user_system(user_id)
    
    return jsonify({
        'authenticated': True,
        'user_id': user_id,
        'has_private_key': system['key_gen'].private_key is not None,
        'has_public_key': system['key_gen'].public_key is not None,
        'team_members': len(system['key_gen'].team_public_keys)
    })

# ============================================================================
# GESTIÓN DE LLAVES
# ============================================================================

@app.route('/api/keys/generate', methods=['POST'])
@login_required
def generate_keys():
    """Generar par de llaves RSA"""
    user_id = session['user_id']
    system = get_user_system(user_id)
    
    try:
        public_key_pem = system['key_gen'].generate_key_pair()
        
        # Registrar llave pública en equipo automáticamente
        system['key_gen'].add_team_member_public_key(user_id, public_key_pem)
        system['key_gen'].save_public_keys_to_file("team_public_keys.json")
        
        return jsonify({
            'success': True,
            'message': 'Llaves generadas exitosamente',
            'files': {
                'private': f'private_key_{user_id}.pem',
                'public': f'public_key_{user_id}.pem'
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/keys/status', methods=['GET'])
@login_required
def keys_status():
    """Obtener estado de las llaves del usuario"""
    user_id = session['user_id']
    system = get_user_system(user_id)
    
    private_key_file = f'private_key_{user_id}.pem'
    public_key_file = f'public_key_{user_id}.pem'
    
    return jsonify({
        'user_id': user_id,
        'private_key_loaded': system['key_gen'].private_key is not None,
        'public_key_loaded': system['key_gen'].public_key is not None,
        'private_key_file_exists': os.path.exists(private_key_file),
        'public_key_file_exists': os.path.exists(public_key_file),
        'team_members': list(system['key_gen'].team_public_keys.keys())
    })

@app.route('/api/keys/team/add', methods=['POST'])
@login_required
def add_team_member():
    """Agregar miembro al equipo"""
    user_id = session['user_id']
    system = get_user_system(user_id)
    
    data = request.json
    member_id = data.get('member_id')
    
    if not member_id:
        return jsonify({'error': 'member_id requerido'}), 400
    
    # Buscar archivo de llave pública
    public_key_file = f'public_key_{member_id}.pem'
    
    if not os.path.exists(public_key_file):
        return jsonify({'error': f'No se encontró {public_key_file}'}), 404
    
    try:
        with open(public_key_file, 'r') as f:
            public_key_pem = f.read()
        
        if system['key_gen'].add_team_member_public_key(member_id, public_key_pem):
            system['key_gen'].save_public_keys_to_file("team_public_keys.json")
            return jsonify({
                'success': True,
                'message': f'Miembro {member_id} agregado al equipo'
            })
        else:
            return jsonify({'error': 'No se pudo agregar el miembro'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/keys/team/list', methods=['GET'])
@login_required
def list_team_members():
    """Listar miembros del equipo"""
    user_id = session['user_id']
    system = get_user_system(user_id)
    
    members = []
    for member_id in system['key_gen'].team_public_keys.keys():
        private_key_exists = os.path.exists(f'private_key_{member_id}.pem')
        members.append({
            'id': member_id,
            'has_public_key': True,
            'has_private_key': private_key_exists
        })
    
    return jsonify({'members': members})

# ============================================================================
# GESTIÓN DE DOCUMENTOS
# ============================================================================

@app.route('/api/documents/upload', methods=['POST'])
@login_required
def upload_document():
    """Subir documento"""
    if 'file' not in request.files:
        return jsonify({'error': 'No se envió archivo'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Nombre de archivo vacío'}), 400
    
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    return jsonify({
        'success': True,
        'filename': filename,
        'path': filepath,
        'size': os.path.getsize(filepath)
    })

@app.route('/api/documents/list', methods=['GET'])
@login_required
def list_documents():
    """Listar documentos disponibles"""
    documents = []
    
    # Listar archivos en uploads
    if os.path.exists(app.config['UPLOAD_FOLDER']):
        for filename in os.listdir(app.config['UPLOAD_FOLDER']):
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.isfile(filepath):
                # Buscar si tiene firma
                sig_file = os.path.join('signatures', f'firma_{filename}.json')
                has_signature = os.path.exists(sig_file)
                
                # Buscar si está cifrado
                enc_file = filepath + '.enc'
                is_encrypted = os.path.exists(enc_file)
                
                documents.append({
                    'name': filename,
                    'size': os.path.getsize(filepath),
                    'path': filepath,
                    'has_signature': has_signature,
                    'is_encrypted': is_encrypted,
                    'modified': datetime.fromtimestamp(
                        os.path.getmtime(filepath)
                    ).isoformat()
                })
    
    return jsonify({'documents': documents})

# ============================================================================
# FIRMAS DIGITALES
# ============================================================================

@app.route('/api/sign/document', methods=['POST'])
@login_required
def sign_document():
    """Firmar un documento"""
    user_id = session['user_id']
    system = get_user_system(user_id)
    
    if not system['key_gen'].private_key:
        return jsonify({'error': 'No hay llave privada cargada'}), 400
    
    data = request.json
    file_path = data.get('file_path')
    
    if not file_path or not os.path.exists(file_path):
        return jsonify({'error': 'Archivo no encontrado'}), 404
    
    try:
        # Crear firma
        signature_package = system['signer'].sign_document(file_path)
        
        # Guardar firma
        signature_file = os.path.join('signatures', f'firma_{user_id}_{os.path.basename(file_path)}.json')
        saved_path = system['signer'].save_signature_package(signature_package, signature_file)
        
        return jsonify({
            'success': True,
            'signature_file': saved_path,
            'document_hash': signature_package['document_hash'],
            'signer': user_id
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sign/verify', methods=['POST'])
@login_required
def verify_signature():
    """Verificar firma de un documento"""
    user_id = session['user_id']
    system = get_user_system(user_id)
    
    data = request.json
    file_path = data.get('file_path')
    signature_file = data.get('signature_file')
    
    if not file_path or not os.path.exists(file_path):
        return jsonify({'error': 'Documento no encontrado'}), 404
    
    if not signature_file or not os.path.exists(signature_file):
        return jsonify({'error': 'Archivo de firma no encontrado'}), 404
    
    try:
        with open(signature_file, 'r') as f:
            signature_package = json.load(f)
        
        valid = system['verifier'].verify_signature(signature_package, file_path)
        
        return jsonify({
            'valid': valid,
            'signer': signature_package.get('user_id', 'desconocido'),
            'document_hash': signature_package.get('document_hash'),
            'timestamp': signature_package.get('timestamp')
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sign/verify-multiple', methods=['POST'])
@login_required
def verify_multiple_signatures():
    """Verificar múltiples firmas de un documento"""
    user_id = session['user_id']
    system = get_user_system(user_id)
    
    data = request.json
    file_path = data.get('file_path')
    signature_files = data.get('signature_files', [])
    
    if not file_path or not os.path.exists(file_path):
        return jsonify({'error': 'Documento no encontrado'}), 404
    
    results = []
    all_valid = True
    
    for sig_file in signature_files:
        if not os.path.exists(sig_file):
            results.append({
                'file': sig_file,
                'valid': False,
                'error': 'Archivo no encontrado'
            })
            all_valid = False
            continue
        
        try:
            with open(sig_file, 'r') as f:
                signature_package = json.load(f)
            
            valid = system['verifier'].verify_signature(signature_package, file_path)
            
            results.append({
                'file': sig_file,
                'valid': valid,
                'signer': signature_package.get('user_id', 'desconocido'),
                'timestamp': signature_package.get('timestamp')
            })
            
            if not valid:
                all_valid = False
                
        except Exception as e:
            results.append({
                'file': sig_file,
                'valid': False,
                'error': str(e)
            })
            all_valid = False
    
    return jsonify({
        'all_valid': all_valid,
        'total': len(signature_files),
        'valid_count': sum(1 for r in results if r.get('valid')),
        'results': results
    })

# ============================================================================
# CIFRADO Y DESCIFRADO
# ============================================================================

@app.route('/api/password/generate', methods=['POST'])
@login_required
def generate_aes_password():
    """Generar contraseña AES aleatoria"""
    try:
        # Generar 32 bytes aleatorios para AES-256
        import secrets
        aes_key = secrets.token_bytes(32)
        aes_key_b64 = base64.b64encode(aes_key).decode('utf-8')
        
        return jsonify({
            'success': True,
            'aes_key': aes_key_b64,
            'message': 'Contraseña AES generada exitosamente'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/password/encrypt', methods=['POST'])
@login_required
def encrypt_password():
    """Cifrar contraseña AES con llave pública de un miembro"""
    user_id = session['user_id']
    system = get_user_system(user_id)
    
    data = request.json
    aes_password = data.get('aes_password')
    member_id = data.get('member_id')
    
    if not aes_password or not member_id:
        return jsonify({'error': 'Faltan parámetros'}), 400
    
    try:
        # Guardar temporalmente la contraseña en un archivo
        temp_password_file = f'temp_password_{user_id}.txt'
        with open(temp_password_file, 'w') as f:
            f.write(aes_password)
        
        # Cifrar con la llave pública del miembro
        result = system['key_encryptor'].encrypt_key_for_member(
            temp_password_file, 
            member_id,
            system['key_gen']
        )
        
        # Eliminar archivo temporal
        if os.path.exists(temp_password_file):
            os.remove(temp_password_file)
        
        if result['success']:
            return jsonify({
                'success': True,
                'encrypted_file': result['encrypted_file'],
                'member_id': member_id
            })
        else:
            return jsonify({'error': result.get('error', 'Error desconocido')}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/password/decrypt', methods=['POST'])
@login_required
def decrypt_password():
    """Descifrar contraseña AES con llave privada"""
    user_id = session['user_id']
    system = get_user_system(user_id)
    
    if not system['key_gen'].private_key:
        return jsonify({'error': 'No hay llave privada cargada'}), 400
    
    data = request.json
    encrypted_file = data.get('encrypted_file')
    
    if not encrypted_file:
        return jsonify({'error': 'Falta parámetro encrypted_file'}), 400
    
    if not os.path.exists(encrypted_file):
        return jsonify({'error': 'Archivo no encontrado'}), 404
    
    try:
        result = system['key_decryptor'].decrypt_password(
            encrypted_file,
            system['key_gen'].private_key
        )
        
        if result['success']:
            return jsonify({
                'success': True,
                'aes_password': result['decrypted_password']
            })
        else:
            return jsonify({'error': result.get('error', 'Error desconocido')}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/encrypt/document', methods=['POST'])
@login_required
def encrypt_document():
    """Cifrar documento"""
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
                'metadata_file': result['metadata_path'],
                'original_size': os.path.getsize(file_path),
                'encrypted_size': os.path.getsize(result['encrypted_path'])
            })
        else:
            return jsonify({'error': result.get('error', 'Error desconocido')}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/decrypt/document', methods=['POST'])
@login_required
def decrypt_document():
    """Descifrar documento"""
    user_id = session['user_id']
    system = get_user_system(user_id)
    
    data = request.json
    encrypted_file = data.get('encrypted_file')
    metadata_file = data.get('metadata_file')
    password = data.get('password')
    
    if not all([encrypted_file, metadata_file, password]):
        return jsonify({'error': 'Faltan parámetros'}), 400
    
    if not os.path.exists(encrypted_file) or not os.path.exists(metadata_file):
        return jsonify({'error': 'Archivos no encontrados'}), 404
    
    try:
        result = system['decryptor'].decrypt_document(encrypted_file, metadata_file, password)
        
        if result['success']:
            return jsonify({
                'success': True,
                'decrypted_file': result['decrypted_path'],
                'original_filename': result['original_filename']
            })
        else:
            return jsonify({'error': result.get('error', 'Error desconocido')}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# DESCARGAS
# ============================================================================

@app.route('/api/download/<path:filename>', methods=['GET'])
@login_required
def download_file(filename):
    """Descargar archivo"""
    # Buscar archivo en diferentes carpetas
    for folder in ['uploads', 'encrypted', 'signatures', '.']:
        filepath = os.path.join(folder, filename)
        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True)
    
    return jsonify({'error': 'Archivo no encontrado'}), 404

# ============================================================================
# ESTADÍSTICAS
# ============================================================================

@app.route('/api/stats/dashboard', methods=['GET'])
@login_required
def dashboard_stats():
    """Obtener estadísticas para el dashboard"""
    user_id = session['user_id']
    system = get_user_system(user_id)
    
    # Contar documentos
    total_documents = 0
    signed_documents = 0
    encrypted_documents = 0
    
    if os.path.exists(app.config['UPLOAD_FOLDER']):
        for filename in os.listdir(app.config['UPLOAD_FOLDER']):
            if os.path.isfile(os.path.join(app.config['UPLOAD_FOLDER'], filename)):
                total_documents += 1
                
                # Verificar si tiene firma
                sig_file = os.path.join('signatures', f'firma_{filename}.json')
                if os.path.exists(sig_file):
                    signed_documents += 1
                
                # Verificar si está cifrado
                enc_file = os.path.join(app.config['UPLOAD_FOLDER'], filename + '.enc')
                if os.path.exists(enc_file):
                    encrypted_documents += 1
    
    return jsonify({
        'total_documents': total_documents,
        'signed_documents': signed_documents,
        'encrypted_documents': encrypted_documents,
        'team_members': len(system['key_gen'].team_public_keys),
        'has_private_key': system['key_gen'].private_key is not None,
        'has_public_key': system['key_gen'].public_key is not None
    })

# ============================================================================
# INICIAR SERVIDOR
# ============================================================================

if __name__ == '__main__':
    print("=" * 60)
    print("  SERVIDOR API - SISTEMA CRIPTOGRÁFICO LEGAL")
    print("=" * 60)
    print(f"Servidor ejecutándose en: http://localhost:5000")
    print(f"Carpeta de uploads: {app.config['UPLOAD_FOLDER']}")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)
