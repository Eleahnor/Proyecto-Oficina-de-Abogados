import os
import json
import base64
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from sign.key_generator import KeyGenerator
from sign.signature_verifier import Signverify

class Signverify:
    def __init__(self, key_generator=None):
        self.key_gen = key_generator
    
    def set_key_generator(self, key_generator):
        """Establece el generador de llaves a usar"""
        self.key_gen = key_generator
    
    def calculate_document_hash(self, file_path):
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except FileNotFoundError:
            raise ValueError(f"❌ Archivo no encontrado: {file_path}")
    
    def verify_signature(self, signature_package, file_path):
        """Verifica una firma individual"""
        try:
            # Verificar integridad del documento
            current_hash = self.calculate_document_hash(file_path)
            if signature_package['document_hash'] != current_hash:
                print("❌ ALERTA: El documento ha sido modificado después de la firma!")
                return False
            
            # Obtener usuario y llave pública
            user_id = signature_package['user_id']
            if not self.key_gen or user_id not in self.key_gen.team_public_keys:
                print(f"❌ Llave pública no encontrada para el usuario: {user_id}")
                return False
            
            public_key = self.key_gen.team_public_keys[user_id]
            
            # Leer documento
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Verificar firma
            signature = base64.b64decode(signature_package['signature'])
            
            if signature_package.get('hash_only', False):
                # Verificar firma del hash
                public_key.verify(
                    signature,
                    signature_package['document_hash'].encode('utf-8'),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            else:
                # Verificar firma del documento completo
                public_key.verify(
                    signature,
                    file_data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            
            print(f"✅ Firma de {user_id} verificada correctamente")
            return True
            
        except InvalidSignature:
            print(f"❌ Firma inválida de {signature_package.get('user_id', 'desconocido')}")
            return False
        except Exception as e:
            print(f"❌ Error verificando firma de {signature_package.get('user_id', 'desconocido')}: {e}")
            return False
    
    def verify_signatures_interactive(self, file_path):
        """Verificación interactiva de múltiples firmas"""
        print("\n=== VERIFICACIÓN DE MÚLTIPLES FIRMAS ===")
        
        if not os.path.exists(file_path):
            print("❌ El documento no existe.")
            return False
        
        # Verificar integridad del documento primero
        document_hash = self.calculate_document_hash(file_path)
        print(f"🔍 Hash del documento: {document_hash}")
        
        while True:
            try:
                num_firmas = int(input("\n¿Cuántas firmas deseas verificar? "))
                if num_firmas > 0:
                    break
                else:
                    print("Por favor, ingresa un número mayor que 0.")
            except ValueError:
                print("Por favor, ingresa un número válido.")
        
        # Obtener archivos de firma
        signature_files = []
        for i in range(num_firmas):
            while True:
                nombre_archivo = input(f"📁 Ingresa el archivo de firma #{i+1}: ").strip()
                if nombre_archivo:
                    if not nombre_archivo.endswith('.json'):
                        nombre_archivo += '.json'
                    signature_files.append(nombre_archivo)
                    break
                else:
                    print("El nombre no puede estar vacío.")
        
        print(f"\n🔍 Verificando {num_firmas} firmas para el documento...")
        print("-" * 50)
        
        valid_signatures = 0
        invalid_signatures = 0
        verification_results = []
        
        # Verificar cada firma individualmente
        for sig_file in signature_files:
            try:
                with open(sig_file, 'r') as f:
                    signature_package = json.load(f)
                
                # Verificar si el hash coincide
                if signature_package.get('document_hash') != document_hash:
                    print(f"❌ {sig_file}: Hash no coincide con el documento")
                    invalid_signatures += 1
                    verification_results.append({
                        'file': sig_file,
                        'user': signature_package.get('user_id', 'desconocido'),
                        'status': 'HASH_MISMATCH'
                    })
                    continue
                
                # Verificar firma
                if self.verify_signature(signature_package, file_path):
                    valid_signatures += 1
                    verification_results.append({
                        'file': sig_file,
                        'user': signature_package.get('user_id', 'desconocido'),
                        'status': 'VALID'
                    })
                else:
                    invalid_signatures += 1
                    verification_results.append({
                        'file': sig_file,
                        'user': signature_package.get('user_id', 'desconocido'),
                        'status': 'INVALID_SIGNATURE'
                    })
                    
            except FileNotFoundError:
                print(f"❌ Archivo de firma no encontrado: {sig_file}")
                invalid_signatures += 1
                verification_results.append({
                    'file': sig_file,
                    'user': 'desconocido',
                    'status': 'FILE_NOT_FOUND'
                })
            except json.JSONDecodeError:
                print(f"❌ Error de formato en archivo: {sig_file}")
                invalid_signatures += 1
                verification_results.append({
                    'file': sig_file,
                    'user': 'desconocido',
                    'status': 'INVALID_JSON'
                })
            except Exception as e:
                print(f"❌ Error procesando {sig_file}: {e}")
                invalid_signatures += 1
                verification_results.append({
                    'file': sig_file,
                    'user': 'desconocido',
                    'status': 'ERROR'
                })
        
        # Mostrar resumen
        print("-" * 50)
        print(f"✅ Firmas válidas: {valid_signatures}")
        print(f"❌ Firmas inválidas: {invalid_signatures}")
        print(f"📊 Total de firmas verificadas: {num_firmas}")
        
        # Mostrar detalles
        print("\n--- DETALLES DE VERIFICACIÓN ---")
        for result in verification_results:
            status_icon = "✅" if result['status'] == 'VALID' else "❌"
            print(f"{status_icon} {result['file']} - {result['user']} - {result['status']}")
        
        if valid_signatures == num_firmas:
            print("\n🎉 ¡TODAS las firmas son válidas!")
            return True
        else:
            print(f"\n⚠️  Solo {valid_signatures} de {num_firmas} firmas son válidas.")
            return False
    
    def verify_collected_signatures(self, collected_file, file_path):
        """Verifica firmas desde un archivo recolectado"""
        try:
            with open(collected_file, 'r') as f:
                collected_data = json.load(f)
            
            print(f"\n🔍 Verificando {collected_data['total_signatures']} firmas recolectadas...")
            
            valid_count = 0
            for signature in collected_data['signatures']:
                if self.verify_signature(signature, file_path):
                    valid_count += 1
            
            print(f"\n📊 Resultado: {valid_count}/{collected_data['total_signatures']} firmas válidas")
            return valid_count == collected_data['total_signatures']
            
        except Exception as e:
            print(f"❌ Error verificando firmas recolectadas: {e}")
            return False

# Función interactiva para verificación
def verificar_firmas_interactive():
    """Función interactiva para verificar firmas"""
    print("\n--- VERIFICACIÓN DE FIRMAS ---")
    
    # Cargar llaves públicas primero
    key_gen = KeyGenerator()
    if not key_gen.load_public_keys_from_file("public_keys.json"):
        print("❌ No se pudieron cargar las llaves públicas. Regístralas primero.")
        return
    
    verifier = Signverify(key_gen)
    
    documento = input("Ruta del documento a verificar: ").strip()
    
    if not os.path.exists(documento):
        print("❌ El documento no existe.")
        return
    
    # Verificación interactiva
    verifier.verify_signatures_interactive(documento)