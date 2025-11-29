from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from sign.mainhearth import signverify
from mock_data import load_employee_data, update_employee_public_key, update_employee_signature
import json
import os
import tempfile

app = Flask(__name__)
app.secret_key = 'director-secret-key-2024'

# Configuración GitHub
GITHUB_CONFIG = {
    'token': 'ghp_tu_token_de_github',  # Reemplazar con tu token real
    'owner': 'tu_usuario_github',
    'repo_name': 'documentos-legales'
}

# Almacenamiento en memoria
director_system = signverify("director", GITHUB_CONFIG['token'], GITHUB_CONFIG)

@app.route('/')
def index():
    if 'user_role' not in session or session['user_role'] != 'director':
        return redirect(url_for('login_page'))
    return render_template('director.html')

@app.route('/login')
def login_page():
    return render_template('director_login.html')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    password = data.get('password')
    
    if password == 'password': # pass fija solo para pruebas
        session['user_role'] = 'director'
        session['user_id'] = 'director'
        
        # Cargar llaves del director
        if not director_system.load_privk("director"):
            # Si no existen, generar nuevas
            director_system.gen_kpair()
        
        return jsonify({
            'success': True, 
            'message': 'Bienvenido Director',
            'has_keys': director_system.private_key is not None
        })
    
    return jsonify({'success': False, 'error': 'Contraseña incorrecta'})

@app.route('/api/generate-director-keys', methods=['POST'])
def generate_director_keys():
    """Genera llaves para el director"""
    public_key_pem = director_system.gen_kpair()
    
    return jsonify({
        'success': True,
        'message': 'Llaves del director generadas exitosamente',
        'public_key': public_key_pem
    })

@app.route('/api/get-celulas', methods=['GET'])
def get_celulas():
    """Obtiene la lista de células"""
    employees_data = load_employee_data()
    
    celulas = []
    for celula_name, members in employees_data.items():
        celula_info = {
            'nombre': celula_name,
            'miembros_count': len(members),
            'miembros': []
        }
        
        for member in members:
            celula_info['miembros'].append({
                'id': member['id'],
                'nombre_completo': f"{member['nombre']} {member['apellido1']} {member['apellido2']}",
                'cedula': member['cedula'],
                'tiene_llave_publica': member['public_key'] is not None,
                'firma': member['firma']
            })
        
        celulas.append(celula_info)
    
    return jsonify({'celulas': celulas})

@app.route('/api/get-celula/<celula_name>', methods=['GET'])
def get_celula(celula_name):
    """Obtiene los detalles de una célula específica"""
    employees_data = load_employee_data()
    
    if celula_name not in employees_data:
        return jsonify({'error': 'Célula no encontrada'}), 404
    
    miembros = []
    for member in employees_data[celula_name]:
        member_info = {
            'id': member['id'],
            'nombre_completo': f"{member['nombre']} {member['apellido1']} {member['apellido2']}",
            'cedula': member['cedula'],
            'public_key': member['public_key'],
            'firma': member['firma'],
            'tiene_llave_publica': member['public_key'] is not None,
            'tiene_firma': member['firma'] is not None
        }
        miembros.append(member_info)
    
    return jsonify({
        'celula': celula_name,
        'miembros': miembros
    })

# ========== NUEVOS ENDPOINTS PARA GITHUB ==========

@app.route('/api/publish-document', methods=['POST'])
def publish_document():
    """Publica un documento en GitHub para un equipo específico"""
    if 'user_role' not in session or session['user_role'] != 'director':
        return jsonify({'error': 'No autorizado'}), 401
    
    try:
        # Verificar que el director tenga llaves
        if not director_system.private_key:
            return jsonify({'error': 'El director debe generar sus llaves primero'}), 400
        
        file = request.files.get('document')
        team_name = request.form.get('team_name')
        document_name = request.form.get('document_name', file.filename if file else 'documento')
        
        if not file:
            return jsonify({'error': 'No se proporcionó archivo'}), 400
        
        if not team_name:
            return jsonify({'error': 'No se especificó equipo'}), 400
        
        # Verificar que el equipo existe
        available_teams = director_system.get_available_teams('director')
        if team_name not in available_teams:
            return jsonify({'error': f'Equipo no válido: {team_name}'}), 400
        
        # Guardar archivo temporal
        temp_dir = tempfile.gettempdir()
        temp_path = os.path.join(temp_dir, file.filename)
        file.save(temp_path)
        
        try:
            # Publicar en GitHub
            result = director_system.publish_to_github(temp_path, team_name)
            
            # Registrar llaves públicas de los miembros del equipo
            employees_data = load_employee_data()
            if team_name in employees_data:
                for member in employees_data[team_name]:
                    if member['public_key']:
                        director_system.add_team_member_public_key(member['id'], member['public_key'])
            
            return jsonify({
                'success': True,
                'message': 'Documento publicado exitosamente en GitHub',
                'document_hash': result['document_hash'],
                'github_url': result['github_url'],
                'team': team_name
            })
            
        finally:
            # Limpiar archivo temporal
            if os.path.exists(temp_path):
                os.remove(temp_path)
                
    except Exception as e:
        return jsonify({'error': f'Error publicando documento: {str(e)}'}), 500

@app.route('/api/get-published-documents', methods=['GET'])
def get_published_documents():
    """Obtiene documentos publicados disponibles para el director"""
    if 'user_role' not in session or session['user_role'] != 'director':
        return jsonify({'error': 'No autorizado'}), 401
    
    try:
        documents = director_system.get_published_documents('director')
        
        documents_list = []
        for doc_hash, doc_info in documents.items():
            documents_list.append({
                'hash': doc_hash,
                'file_name': doc_info['file_name'],
                'team': doc_info['team'],
                'published_at': doc_info['published_at'],
                'github_url': doc_info.get('github_url', '')
            })
        
        return jsonify({
            'success': True,
            'documents': documents_list
        })
        
    except Exception as e:
        return jsonify({'error': f'Error obteniendo documentos: {str(e)}'}), 500

@app.route('/api/get-available-teams', methods=['GET'])
def get_available_teams():
    """Obtiene equipos disponibles para el director"""
    if 'user_role' not in session or session['user_role'] != 'director':
        return jsonify({'error': 'No autorizado'}), 401
    
    try:
        teams = director_system.get_available_teams('director')
        
        teams_info = []
        for team in teams:
            # Contar miembros del equipo
            employees_data = load_employee_data()
            member_count = len(employees_data.get(team, []))
            
            teams_info.append({
                'name': team,
                'member_count': member_count,
                'description': f'Equipo {team} con {member_count} miembros'
            })
        
        return jsonify({
            'success': True,
            'teams': teams_info
        })
        
    except Exception as e:
        return jsonify({'error': f'Error obteniendo equipos: {str(e)}'}), 500

@app.route('/api/verify-document-signatures', methods=['POST'])
def verify_document_signatures():
    """Verifica las firmas de un documento publicado"""
    if 'user_role' not in session or session['user_role'] != 'director':
        return jsonify({'error': 'No autorizado'}), 401
    
    try:
        data = request.get_json()
        document_hash = data.get('document_hash')
        
        if not document_hash:
            return jsonify({'error': 'Hash de documento no proporcionado'}), 400
        
        # Obtener información del documento
        if document_hash not in director_system.published_documents:
            return jsonify({'error': 'Documento no encontrado'}), 404
        
        doc_info = director_system.published_documents[document_hash]
        team_name = doc_info['team']
        
        # Descargar firmas desde GitHub
        if director_system.github_enabled:
            signatures = director_system.github_mgr.download_signatures(document_hash, team_name)
        else:
            signatures = []
        
        # Verificar cada firma
        verification_results = []
        valid_signatures = 0
        
        for signature_data in signatures:
            user_id = signature_data.get('user_id')
            try:
                # Verificar firma del hash
                is_valid = director_system.verify_hash_signature(
                    user_id, 
                    document_hash, 
                    signature_data['signature']
                )
                
                verification_results.append({
                    'user_id': user_id,
                    'valid': is_valid,
                    'timestamp': signature_data.get('timestamp', '')
                })
                
                if is_valid:
                    valid_signatures += 1
                    
            except Exception as e:
                verification_results.append({
                    'user_id': user_id,
                    'valid': False,
                    'error': str(e)
                })
        
        return jsonify({
            'success': True,
            'document_hash': document_hash,
            'file_name': doc_info['file_name'],
            'team': team_name,
            'total_signatures': len(signatures),
            'valid_signatures': valid_signatures,
            'verification_results': verification_results
        })
        
    except Exception as e:
        return jsonify({'error': f'Error verificando firmas: {str(e)}'}), 500

@app.route('/api/director-status', methods=['GET'])
def get_director_status():
    """Obtiene estado completo del sistema del director"""
    if 'user_role' not in session or session['user_role'] != 'director':
        return jsonify({'error': 'No autorizado'}), 401
    
    try:
        # Información de llaves
        keys_status = {
            'has_private_key': director_system.private_key is not None,
            'has_public_key': director_system.public_key is not None,
            'team_keys_count': len(director_system.team_public_keys)
        }
        
        # Información de GitHub
        github_status = {
            'enabled': director_system.github_enabled,
            'published_documents_count': len(director_system.published_documents)
        }
        
        # Información de equipos
        available_teams = director_system.get_available_teams('director')
        employees_data = load_employee_data()
        
        teams_status = []
        for team in available_teams:
            members = employees_data.get(team, [])
            members_with_keys = [m for m in members if m.get('public_key')]
            
            teams_status.append({
                'name': team,
                'total_members': len(members),
                'members_with_keys': len(members_with_keys)
            })
        
        return jsonify({
            'success': True,
            'keys': keys_status,
            'github': github_status,
            'teams': teams_status,
            'user_id': session['user_id']
        })
        
    except Exception as e:
        return jsonify({'error': f'Error obteniendo estado: {str(e)}'}), 500

# ========== ENDPOINTS EXISTENTES (MANTENIDOS) ==========

@app.route('/api/distribute-keys', methods=['POST'])
def distribute_keys():
    """Distribuye llaves simétricas a una célula"""
    data = request.get_json()
    celula_name = data.get('celula_name')
    key_name = data.get('key_name', 'llave_celula')
    
    employees_data = load_employee_data()
    
    if celula_name not in employees_data:
        return jsonify({'error': 'Célula no encontrada'}), 404
    
    # Verificar que el director tenga llaves
    if not director_system.public_key:
        return jsonify({'error': 'El director debe generar sus llaves primero'}), 400
    
    # Para GitHub, no necesitamos llaves simétricas, pero mantenemos la función
    # por compatibilidad con el código existente
    
    return jsonify({
        'success': True,
        'message': f'Configuración de equipo {celula_name} completada',
        'team_configured': True
    })

@app.route('/api/verify-signature', methods=['POST'])
def verify_signature():
    """Verifica firma de un empleado (mantenido por compatibilidad)"""
    data = request.get_json()
    employee_id = data.get('employee_id')
    message = data.get('message', 'Mensaje de verificación')
    
    employees_data = load_employee_data()
    
    # Buscar empleado y su llave pública
    employee_public_key = None
    employee_signature = None
    
    for celula in employees_data.values():
        for employee in celula:
            if employee['id'] == employee_id:
                employee_public_key = employee['public_key']
                employee_signature = employee['firma']
                break
    
    if not employee_public_key or not employee_signature:
        return jsonify({'error': 'Empleado no encontrado o sin firma'}), 404
    
    # Aquí necesitarías implementar verify_signature si no existe
    # Por ahora retornamos un mensaje informativo
    return jsonify({
        'success': True,
        'message': 'Función de verificación en desarrollo',
        'employee_id': employee_id
    })

@app.route('/api/director-keys', methods=['GET'])
def get_director_keys():
    """Obtiene información de las llaves del director"""
    return jsonify({
        'has_keys': director_system.public_key is not None,
        'public_key': director_system.get_public_key_pem() if director_system.public_key else None,
        'symmetric_keys_count': len(director_system.symmetric_keys),
        'github_enabled': director_system.github_enabled
    })

@app.route('/api/logout', methods=['POST'])
def logout():
    """Cierra la sesión del director"""
    session.clear()
    return jsonify({'success': True, 'message': 'Sesión cerrada'})

if __name__ == '__main__':
    from mock_data import load_employee_data
    load_employee_data()
    
    print("=== Sistema del Director ===")
    print("URL: http://localhost:5001")
    print("Contraseña: password")
    print("GitHub: " + ("✅ Configurado" if director_system.github_enabled else "❌ No configurado"))
    print("=============================")
    
    app.run(debug=True, host='0.0.0.0', port=5001)