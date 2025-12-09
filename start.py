#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Script de inicio para el Sistema Web de Gestión Legal
Verifica dependencias y estructura de directorios antes de iniciar el servidor
"""

import os
import sys

def print_header():
    print("=" * 70)
    print(" " * 15 + "⚖️  SISTEMA WEB DE GESTIÓN LEGAL  ⚖️")
    print("=" * 70)
    print()

def check_dependencies():
    """Verifica que las dependencias estén instaladas"""
    print("📦 Verificando dependencias...")
    
    dependencies = {
        'flask': 'Flask',
        'cryptography': 'cryptography',
        'werkzeug': 'Werkzeug'
    }
    
    missing = []
    for module, name in dependencies.items():
        try:
            __import__(module)
            print(f"  ✅ {name}")
        except ImportError:
            print(f"  ❌ {name} - NO INSTALADO")
            missing.append(name)
    
    if missing:
        print("\n⚠️  Faltan dependencias. Instala con:")
        print(f"    pip install {' '.join(missing.lower())}")
        return False
    
    print("  ✅ Todas las dependencias instaladas\n")
    return True

def create_directories():
    """Crea los directorios necesarios"""
    print("📁 Creando estructura de directorios...")
    
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    directories = {
        'templates': 'Plantillas HTML',
        'static': 'Archivos estáticos (JS, CSS)',
        'keys': 'Llaves RSA',
        'documents': 'Documentos del equipo',
        'uploads': 'Archivos temporales',
        'signatures': 'Firmas digitales',
        'sign': 'Módulo de firmas',
        'cipher': 'Módulo de cifrado'
    }
    
    for dir_name, description in directories.items():
        dir_path = os.path.join(base_dir, dir_name)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path, exist_ok=True)
            print(f"  ✅ Creado: {dir_name}/ - {description}")
        else:
            print(f"  ✓  Existe: {dir_name}/")
    
    # Crear archivos __init__.py
    for module in ['sign', 'cipher']:
        init_file = os.path.join(base_dir, module, '__init__.py')
        if not os.path.exists(init_file):
            with open(init_file, 'w') as f:
                f.write("# Module initialization\n")
            print(f"  ✅ Creado: {module}/__init__.py")
    
    print()

def check_module_files():
    """Verifica que los módulos necesarios existan"""
    print("🔍 Verificando módulos del sistema...")
    
    required_files = {
        'sign/key_generator.py': 'Generador de llaves',
        'sign/digital_signer.py': 'Firmador digital',
        'sign/signature_verifier.py': 'Verificador de firmas',
        'cipher/Cifrado_doc.py': 'Cifrado de documentos',
        'cipher/Descifrado_doc.py': 'Descifrado de documentos',
        'cipher/cifradollave.py': 'Cifrado de llaves',
        'cipher/decifradollave.py': 'Descifrado de llaves'
    }
    
    missing_files = []
    for filepath, description in required_files.items():
        if os.path.exists(filepath):
            print(f"  ✅ {filepath}")
        else:
            print(f"  ❌ {filepath} - NO ENCONTRADO")
            missing_files.append(filepath)
    
    if missing_files:
        print("\n⚠️  Archivos faltantes. Asegúrate de tener todos los módulos.")
        return False
    
    print("  ✅ Todos los módulos presentes\n")
    return True

def check_templates():
    """Verifica que las plantillas HTML existan"""
    print("🎨 Verificando plantillas...")
    
    templates = {
        'templates/login.html': 'Página de inicio de sesión',
        'templates/dashboard.html': 'Dashboard principal'
    }
    
    missing = []
    for filepath, description in templates.items():
        if os.path.exists(filepath):
            print(f"  ✅ {filepath}")
        else:
            print(f"  ❌ {filepath} - NO ENCONTRADO")
            missing.append(filepath)
    
    if missing:
        print("\n⚠️  Plantillas faltantes.")
        return False
    
    print()
    return True

def check_static_files():
    """Verifica archivos estáticos"""
    print("📄 Verificando archivos estáticos...")
    
    if os.path.exists('static/dashboard.js'):
        print(f"  ✅ static/dashboard.js")
    else:
        print(f"  ❌ static/dashboard.js - NO ENCONTRADO")
        return False
    
    print()
    return True

def print_user_guide():
    """Muestra guía rápida de usuarios"""
    print("👥 USUARIOS PREDEFINIDOS:")
    print("-" * 70)
    
    teams = {
        "Pensión alimenticia": [
            ("Boloñesa", "avril789", "Abogado"),
            ("Ramírez", "mar789", "Cliente"),
            ("Hidalgo", "daniel789", "Cliente"),
            ("Mejía", "avril123", "Notario")
        ],
        "Divorcio": [
            ("Cruz", "daniel456", "Abogado"),
            ("Pérez", "mar456", "Cliente"),
            ("Perejil", "avril456", "Cliente"),
            ("Estrada", "daniel123", "Notario")
        ],
        "Asunto hipotecario": [
            ("Castro", "mar123", "Abogado"),
            ("Pérez", "mar456", "Cliente"),
            ("Estrada", "daniel123", "Notario")
        ]
    }
    
    for team_name, users in teams.items():
        print(f"\n  📋 {team_name}:")
        for username, password, role in users:
            print(f"     • {username:12} | {password:12} | {role}")
    
    print()

def print_instructions():
    """Muestra instrucciones de uso"""
    print("🚀 INSTRUCCIONES DE USO:")
    print("-" * 70)
    print("""
  1. El servidor se iniciará en: http://localhost:5000
  2. Abre tu navegador web en esa dirección
  3. Usa las credenciales de arriba para iniciar sesión
  4. Primera vez: Genera tus llaves RSA en "Gestión de Llaves"
  5. Descarga tu llave privada y guárdala en lugar seguro
  
  📖 Flujo básico:
     Abogado → Sube documento → Genera AES → Cifra → Comparte llave → Firma
     Cliente → Descifra llave AES → Descifra documento → Firma
     
  🔐 Seguridad:
     - RSA 2048 bits para llaves y firmas
     - AES CBC para documentos
     - PSS padding para firmas
     - OAEP padding para cifrado RSA
""")
    print("-" * 70)
    print()

def start_server():
    """Inicia el servidor Flask"""
    print("🚀 Iniciando servidor Flask...")
    print("   Presiona Ctrl+C para detener el servidor\n")
    print("=" * 70)
    print()
    
    # Importar y ejecutar app
    try:
        from app import app
        app.run(debug=True, host='0.0.0.0', port=5000)
    except Exception as e:
        print(f"\n❌ Error al iniciar el servidor: {e}")
        print("\nVerifica que:")
        print("  1. Todos los archivos estén en su lugar")
        print("  2. Las dependencias estén instaladas")
        print("  3. No haya errores de sintaxis en app.py")
        sys.exit(1)

def main():
    """Función principal"""
    print_header()
    
    # Verificaciones
    checks = [
        ("Dependencias", check_dependencies),
        ("Directorios", lambda: (create_directories(), True)[1]),
        ("Módulos", check_module_files),
        ("Plantillas", check_templates),
        ("Archivos estáticos", check_static_files)
    ]
    
    all_ok = True
    for name, check_func in checks:
        result = check_func()
        if not result:
            all_ok = False
            print(f"❌ Falló verificación: {name}\n")
    
    if not all_ok:
        print("⚠️  Hay problemas que deben resolverse antes de iniciar.")
        print("   Revisa los mensajes de error arriba.\n")
        sys.exit(1)
    
    print("✅ Todas las verificaciones pasaron!\n")
    
    # Mostrar información de usuarios
    print_user_guide()
    print_instructions()
    
    # Preguntar si desea continuar
    try:
        input("Presiona ENTER para iniciar el servidor (o Ctrl+C para cancelar)...")
    except KeyboardInterrupt:
        print("\n\n👋 Operación cancelada por el usuario.\n")
        sys.exit(0)
    
    # Iniciar servidor
    start_server()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Servidor detenido. ¡Hasta luego!\n")
        sys.exit(0)
