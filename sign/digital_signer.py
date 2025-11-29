import os
import json
import base64
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

class DigitalSigner:
    def __init__(self, key_generator=None):
        self.key_gen = key_generator
        self.document_hash = None
        
        # Configuración de equipos
        self.teams_config = {
            "legal": ["director", "abogado1", "abogado2"],
            "finanzas": ["director", "contador", "auditor"], 
            "rrhh": ["director", "gerente_rrhh"],
            "confidencial": ["director"]
        }
    
    def set_key_generator(self, key_generator):
        """Establece el generador de llaves a usar"""
        self.key_gen = key_generator
    
    def calculate_document_hash(self, file_path):
        """Calcula hash SHA-256 del documento"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            self.document_hash = sha256_hash.hexdigest()
            return self.document_hash
        except FileNotFoundError:
            raise ValueError(f"❌ Archivo no encontrado: {file_path}")
    
    def sign_document(self, file_path):
        """Firma un documento digitalmente"""
        if not self.key_gen or not self.key_gen.private_key:
            raise ValueError("❌ No hay llave privada disponible")
        
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
        except FileNotFoundError:
            raise ValueError(f"❌ Archivo no encontrado: {file_path}")
        
        # Calcular hash del documento
        document_hash = self.calculate_document_hash(file_path)
        
        # Crear firma digital
        signature = self.key_gen.private_key.sign(
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Crear paquete de firma
        signature_package = {
            'user_id': self.key_gen.user_id,
            'signature': base64.b64encode(signature).decode('utf-8'),
            'document_hash': document_hash,
            'timestamp': self.get_timestamp(),
            'file_name': os.path.basename(file_path)
        }
        
        return signature_package
    
    def sign_document_hash_only(self, document_hash):
        """Firma solo el hash del documento (más eficiente)"""
        if not self.key_gen or not self.key_gen.private_key:
            raise ValueError("❌ No hay llave privada disponible")
        
        signature = self.key_gen.private_key.sign(
            document_hash.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        signature_package = {
            'user_id': self.key_gen.user_id,
            'signature': base64.b64encode(signature).decode('utf-8'),
            'document_hash': document_hash,
            'timestamp': self.get_timestamp(),
            'hash_only': True
        }
        
        return signature_package
    
    def save_signature_package(self, signature_package, output_path=None):
        """Guarda el paquete de firma en un archivo JSON"""
        if output_path is None:
            output_path = f"firma_{self.key_gen.user_id}_{self.get_timestamp()}.json"
        
        with open(output_path, 'w') as f:
            json.dump(signature_package, f, indent=2)
        
        print(f"📝 Firma guardada en: {output_path}")
        return output_path
    
    def collect_signatures_interactive(self):        
        """Recolecta firmas de manera interactiva"""
        print("\n--- COLECCIÓN DE FIRMAS ---")
        
        while True:
            try:
                num_firmas = int(input("¿Cuántas firmas deseas recoger? "))
                if num_firmas > 0:
                    break
                else:
                    print("Por favor, ingresa un número mayor que 0.")
            except ValueError:
                print("Por favor, ingresa un número válido.")
        
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
        
        return self.collect_signatures(signature_files)
    
    def collect_signatures(self, signature_files, output_file="todas_las_firmas.json"):
        """Recolecta múltiples firmas en un solo archivo"""
        all_signatures = {
            'document_hash': self.document_hash,
            'collected_at': self.get_timestamp(),
            'total_signatures': len(signature_files),
            'signatures': []
        }
        
        print(f"\n🔄 Recolectando {len(signature_files)} firmas...")
        
        for sig_file in signature_files:
            try:
                with open(sig_file, 'r') as f:
                    signature_data = json.load(f)
                all_signatures['signatures'].append(signature_data)
                print(f"✅ Firma de {signature_data['user_id']} añadida desde {sig_file}")
            except FileNotFoundError:
                print(f"❌ Archivo no encontrado: {sig_file}")
            except json.JSONDecodeError:
                print(f"❌ Error de formato en: {sig_file}")
            except Exception as e:
                print(f"❌ Error cargando {sig_file}: {e}")
        
        with open(output_file, 'w') as f:
            json.dump(all_signatures, f, indent=2)
        
        print(f"\n📦 Todas las firmas guardadas en: {output_file}")
        return output_file
    
    def user_in_team(self, user_id, team_name):
        """Verifica si usuario pertenece a equipo"""
        return team_name in self.teams_config and user_id in self.teams_config[team_name]
    
    def get_available_teams(self, user_id):
        """Obtiene equipos disponibles para un usuario"""
        return [team for team, members in self.teams_config.items() if user_id in members]
    
    def get_timestamp(self):
        """Obtiene timestamp actual"""
        import time
        return time.time()

# Función interactiva para firmar documentos
def firmar_documento_interactive():
    """Función interactiva para firmar documentos"""
    print("\n--- FIRMA DIGITAL DE DOCUMENTO ---")
    
    user_id = input("Tu ID de usuario: ").strip()
    document_path = input("Ruta del documento a firmar: ").strip()
    
    if not os.path.exists(document_path):
        print("❌ El documento no existe.")
        return
    
    # Configurar generador de llaves y firmador
    key_gen = KeyGenerator(user_id)
    if not key_gen.load_private_key():
        print("❌ No se pudo cargar la llave privada. Genera llaves primero.")
        return
    
    signer = DigitalSigner(key_gen)
    
    try:
        # Firmar documento
        signature_package = signer.sign_document(document_path)
        
        # Guardar firma
        output_file = signer.save_signature_package(signature_package)
        
        print(f"\n🎉 Documento firmado exitosamente!")
        print(f"📄 Documento: {document_path}")
        print(f"🔐 Hash: {signature_package['document_hash']}")
        print(f"👤 Firmado por: {user_id}")
        print(f"📝 Firma guardada en: {output_file}")
        
    except Exception as e:
        print(f"❌ Error firmando documento: {e}")