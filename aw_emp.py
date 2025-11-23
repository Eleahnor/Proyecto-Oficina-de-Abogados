from flask import Flask, render_template, request, jsonify, session
from mainhearth import signverify
from mock_data import load_employee_data, update_employee_public_key, update_employee_signature
import json
import os
import base64

app = Flask(__name__)
app.secret_key = 'empleado-secret-key-2024'

@app.route('/')
def index():
    return render_template('empleado.html')

@app.route('/api/login', methods=['POST'])
def login_empleado():
    data = request.get_json()
    empleado_id = data.get('empleado_id')
    password = data.get('password')
    
    # Verificar credenciales del empleado
    employees_data = load_employee_data()
    empleado_encontrado = None
    celula_empleado = None
    
    for celula_name, miembros in employees_data.items():
        for empleado in miembros:
            if empleado['id'] == empleado_id and empleado['password'] == password:
                empleado_encontrado = empleado
                celula_empleado = celula_name
                break
    
    if empleado_encontrado:
        session['user_role'] = 'empleado'
        session['user_id'] = empleado_id
        session['empleado_info'] = {
            'id': empleado_encontrado['id'],
            'nombre_completo': f"{empleado_encontrado['nombre']} {empleado_encontrado['apellido1']} {empleado_encontrado['apellido2']}",
            'cedula': empleado_encontrado['cedula'],
            'celula': celula_empleado
        }
        
        # Inicializar sistema de llaves para este empleado
        empleado_system = signverify(empleado_id)
        
        # Intentar cargar llave privada si existe
        if empleado_system.load_privk(empleado_id):
            print(f"✓ Llave privada cargada para {empleado_id}")
        
        return jsonify({
            'success': True,
            'message': f'Bienvenido {empleado_encontrado["nombre"]}',
            'empleado_info': session['empleado_info']
        })
    
    return jsonify({'success': False, 'error': 'ID de empleado o contraseña incorrectos'})

@app.route('/api/generate-empleado-keys', methods=['POST'])
def generate_empleado_keys():
    """Genera llaves para el empleado y guarda la pública en el sistema"""
    empleado_id = session.get('user_id')
    
    if not empleado_id:
        return jsonify({'error': 'Empleado no autenticado'}), 401
    
    # Crear sistema de llaves para este empleado
    empleado_system = signverify(empleado_id)
    
    # Generar par de llaves
    public_key_pem = empleado_system.generate_key_pair()
    
    # Guardar la llave pública en el sistema (employees.json)
    if update_employee_public_key(empleado_id, public_key_pem):
        return jsonify({
            'success': True,
            'message': 'Tus llaves han sido generadas exitosamente',
            'public_key': public_key_pem,
            'note': 'Llave privada guardada localmente en tu dispositivo'
        })
    else:
        return jsonify({'error': 'Error al guardar la llave pública en el sistema'}), 500

@app.route('/api/create-signature', methods=['POST'])
def create_signature():
    """Crea una firma digital para el empleado"""
    empleado_id = session.get('user_id')
    data = request.get_json()
    message = data.get('message', 'Mensaje de firma por defecto')
    
    if not empleado_id:
        return jsonify({'error': 'Empleado no autenticado'}), 401
    
    # Cargar sistema de llaves del empleado
    empleado_system = signverify(empleado_id)
    
    if not empleado_system.load_privk(empleado_id):
        return jsonify({'error': 'Debes generar tus llaves primero'}), 400
    
    try:
        # Crear firma digital
        signature = empleado_system.create_signature(message)
        
        # Guardar firma en el sistema
        if update_employee_signature(empleado_id, signature):
            return jsonify({
                'success': True,
                'message': 'Firma digital creada exitosamente',
                'signature': signature,
                'signed_message': message
            })
        else:
            return jsonify({'error': 'Error al guardar la firma en el sistema'}), 500
            
    except Exception as e:
        return jsonify({'error': f'Error creando firma: {str(e)}'}), 500

@app.route('/api/empleado-info', methods=['GET'])
def get_empleado_info():
    """Obtiene información del empleado actual"""
    empleado_info = session.get('empleado_info')
    empleado_id = session.get('user_id')
    
    if not empleado_info or not empleado_id:
        return jsonify({'error': 'Empleado no autenticado'}), 401
    
    # Cargar datos actualizados del empleado
    employees_data = load_employee_data()
    empleado_actualizado = None
    
    for celula in employees_data.values():
        for empleado in celula:
            if empleado['id'] == empleado_id:
                empleado_actualizado = empleado
                break
    
    if empleado_actualizado:
        info = {
            'id': empleado_actualizado['id'],
            'nombre_completo': f"{empleado_actualizado['nombre']} {empleado_actualizado['apellido1']} {empleado_actualizado['apellido2']}",
            'cedula': empleado_actualizado['cedula'],
            'celula': empleado_info['celula'],
            'tiene_llave_publica': empleado_actualizado['public_key'] is not None,
            'tiene_firma': empleado_actualizado['firma'] is not None,
            'public_key': empleado_actualizado['public_key'],
            'firma': empleado_actualizado['firma']
        }
        
        # Verificar si tiene llave privada local
        empleado_system = signverify(empleado_id)
        tiene_llave_privada = empleado_system.load_privk(empleado_id)
        
        return jsonify({
            'success': True,
            'empleado_info': info,
            'tiene_llave_privada': tiene_llave_privada
        })
    
    return jsonify({'error': 'Empleado no encontrado'}), 404

@app.route('/api/decrypt-key', methods=['POST'])
def decrypt_key():
    """Desencripta una llave simétrica recibida"""
    empleado_id = session.get('user_id')
    data = request.get_json()
    encrypted_key_b64 = data.get('encrypted_key')
    
    if not empleado_id:
        return jsonify({'error': 'Empleado no autenticado'}), 401
    
    if not encrypted_key_b64:
        return jsonify({'error': 'Llave encriptada requerida'}), 400
    
    # Cargar sistema de llaves del empleado
    empleado_system = signverify(empleado_id)
    
    if not empleado_system.load_privk(empleado_id):
        return jsonify({'error': 'Debes generar tus llaves primero'}), 400
    
    try:
        # Desencriptar la llave simétrica
        symmetric_key = empleado_system.decrypt_symmetric_key(encrypted_key_b64)
        
        return jsonify({
            'success': True,
            'message': 'Llave simétrica desencriptada exitosamente',
            'symmetric_key_hex': symmetric_key.hex(),
            'symmetric_key_b64': base64.b64encode(symmetric_key).decode('utf-8')
        })
        
    except Exception as e:
        return jsonify({'error': f'Error desencriptando llave: {str(e)}'}), 500

@app.route('/api/logout', methods=['POST'])
def logout_empleado():
    """Cierra la sesión del empleado"""
    session.clear()
    return jsonify({'success': True, 'message': 'Sesión cerrada exitosamente'})

if __name__ == '__main__':
    # Asegurarse de que los datos de empleados existan
    from mock_data import load_employee_data
    load_employee_data()
    
    print("=== Sistema de Empleados ===")
    print("URL: http://localhost:5002")
    print("Credenciales de prueba:")
    print("  ID: emp_001, emp_002, ..., emp_006")
    print("  Contraseña: password")
    print("=============================")
    
    app.run(debug=True, host='0.0.0.0', port=5002)