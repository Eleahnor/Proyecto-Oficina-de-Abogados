from flask import Flask, render_template, request, jsonify, session
from mainhearth import signverify
from mock_data import load_employee_data, update_employee_public_key, update_employee_signature
import json
import os

app = Flask(__name__)
app.secret_key = 'director-secret-key-2024'

# Almacenamiento en memoria
director_system = signverify("director")

@app.route('/')
def index():
    return render_template('director.html')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    password = data.get('password')
    
    if password == 'password': # pass fija solo para pruebas
        session['user_role'] = 'director'
        session['user_id'] = 'director'
        
        director_system.load_privk("director")
        
        return jsonify({
            'success': True, 
            'message': 'Bienvenido Director'
        })
    
    return jsonify({'success': False, 'error': 'Contraseña incorrecta'})

@app.route('/api/generate-director-keys', methods=['POST'])
def generate_director_keys():
    """Genera llaves para el director"""
    public_key_pem = director_system.generate_key_pair()
    
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


# ver celulas de trabajo 
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



# llaves 
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
    
    # Generar llave simétrica
    symmetric_key = director_system.generate_symmetric_key()
    
    # Encriptar para cada miembro de la célula que tenga llave pública
    encrypted_keys = {}
    members_without_keys = []
    
    for member in employees_data[celula_name]:
        if member['public_key']:
            try:
                # Agregar llave pública del miembro al sistema del director
                director_system.add_team_member_public_key(member['id'], member['public_key'])
                
                # Encriptar la llave simétrica
                encrypted_key = director_system.encrypt_symmetric_key(member['id'], symmetric_key)
                encrypted_keys[member['id']] = encrypted_key
            except Exception as e:
                encrypted_keys[member['id']] = f"Error: {str(e)}"
        else:
            members_without_keys.append(member['id'])
    
    # Guardar la llave simétrica
    import base64
    director_system.symmetric_keys[key_name] = base64.b64encode(symmetric_key).decode('utf-8')
    
    return jsonify({
        'success': True,
        'message': f'Llave simétrica distribuida a la célula {celula_name}',
        'encrypted_keys': encrypted_keys,
        'members_without_keys': members_without_keys,
        'symmetric_key_hex': symmetric_key.hex()
    })




@app.route('/api/verify-signature', methods=['POST'])
def verify_signature():
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
    
    # Verificar firma
    is_valid = director_system.verify_signature(
        employee_public_key, 
        message, 
        employee_signature
    )
    
    return jsonify({
        'success': True,
        'is_valid': is_valid,
        'message': 'Firma verificada correctamente' if is_valid else 'Firma inválida'
    })

@app.route('/api/director-keys', methods=['GET'])
def get_director_keys():
    """Obtiene información de las llaves del director"""
    return jsonify({
        'has_keys': director_system.public_key is not None,
        'public_key': director_system.get_public_key_pem(),
        'symmetric_keys_count': len(director_system.symmetric_keys)
    })

if __name__ == '__main__':
    from mock_data import load_employee_data
    load_employee_data()
    
    print("=== Sistema del Director ===")
    print("URL: http://localhost:5001")
    print("Contraseña: password")
    print("=============================")
    
    app.run(debug=True, host='0.0.0.0', port=5001)