import os
import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import utils
import hashlib

class signverify:
    def __init__(self, user_id=None):
        self.private_key = None
        self.public_key = None
        self.user_id = user_id
        self.team_public_keys = {}
        self.symmetric_keys = {}
        self.document_hash = None
        
    def gen_kpair(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        if self.user_id:
            self.save_local()
        
        return self.get_public_key_pem()
    
    def save_local(self):
        if self.private_key and self.user_id:
            private_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            filename = f"private_key_{self.user_id}.pem"
            with open(filename, 'wb') as f:
                f.write(private_pem)
            print(f"Llave privada guardada en: {filename}")
            
            # Guardar llave pública en archivo .pem
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            public_filename = f"public_key_{self.user_id}.pem"
            with open(public_filename, 'wb') as f:
                f.write(public_pem)
            print(f"Llave pública guardada en: {public_filename}")
    
    def load_privk(self, user_id=None):
        user_id = user_id or self.user_id
        if not user_id:
            return False
            
        filename = f"private_key_{user_id}.pem"
        try:
            with open(filename, 'rb') as f:
                private_pem = f.read()
            
            self.private_key = serialization.load_pem_private_key(
                private_pem,
                password=None,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
            self.user_id = user_id
            return True
        except FileNotFoundError:
            return False
    
    def get_public_key_pem(self):
        if self.public_key:
            return self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
        return None
    
    def add_team_member_public_key(self, member_id, public_key_pem):
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            self.team_public_keys[member_id] = public_key
            return True
        except Exception as e:
            print(f"Error cargando llave pública: {e}")
            return False
    
    def calculate_document_hash(self, file_path):
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            self.document_hash = sha256_hash.hexdigest()
            return self.document_hash
        except FileNotFoundError:
            raise ValueError(f"Archivo no encontrado: {file_path}")
    
    def sign_document(self, file_path):
        if not self.private_key:
            raise ValueError("No hay llave privada disponible")
        
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
        except FileNotFoundError:
            raise ValueError(f"Archivo no encontrado: {file_path}")
        
        document_hash = self.calculate_document_hash(file_path)
        
        signature = self.private_key.sign(
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        signature_package = {
            'user_id': self.user_id,
            'signature': base64.b64encode(signature).decode('utf-8'),
            'document_hash': document_hash,
            'timestamp': self.get_timestamp()
        }
        
        return signature_package
    
    def verify_signature(self, signature_package, file_path):
        try:
            current_hash = self.calculate_document_hash(file_path)
            if signature_package['document_hash'] != current_hash:
                print(f"El documento ha sido modificado !!!!!!!!")
                return False
            #
            user_id = signature_package['user_id']
            if user_id not in self.team_public_keys:
                print(f"Llave pública no encontrada para el usuario: {user_id}")
                return False
            
            public_key = self.team_public_keys[user_id]
            #
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # verificar firma
            signature = base64.b64decode(signature_package['signature'])
            
            public_key.verify(
                signature,
                file_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            print(f"✓ Firma de {user_id} verificada correctamente")
            return True
            
        except Exception as e:
            print(f"✗ Error verificando firma de {signature_package.get('user_id', 'desconocido')}: {e}")
            return False
    
    def verify_signatures_interactive(self, file_path):
        print("\n=== VERIFICACIÓN: Multiples Firmas ===")
        
        while True:
            try:
                num_firmas = int(input("\n¿Cuántas firmas deseas verificar? "))
                if num_firmas > 0:
                    break
                else:
                    print("Por favor, ingresa un número mayor que 0.")
            except ValueError:
                print("Por favor, ingresa un número válido.")
        
        # archivos de firma
        signature_files = []
        for i in range(num_firmas):
            while True:
                nombre_archivo = input(f"\nIngresa el nombre del archivo de firma #{i+1}: ").strip()
                if nombre_archivo:
                    if not nombre_archivo.endswith('.json'):
                        nombre_archivo += '.json'
                    signature_files.append(nombre_archivo)
                    break
                else:
                    print("El nombre no puede estar vacío.")
        
        # verificar integridad del documento
        document_hash = self.calculate_document_hash(file_path)
        
        print(f"\nVerificando {num_firmas} firmas para el documento...")
        print(f"Hash del documento: {document_hash}")
        print("-" * 50)
        
        valid_signatures = 0
        invalid_signatures = 0
        
        # Verificar cada firma individualmente
        for sig_file in signature_files:
            try:
                with open(sig_file, 'r') as f:
                    signature_package = json.load(f)
                
                if self.verify_signature(signature_package, file_path):
                    valid_signatures += 1
                else:
                    invalid_signatures += 1
                    
            except FileNotFoundError:
                print(f"✗ Archivo de firma no encontrado: {sig_file}")
                invalid_signatures += 1
            except json.JSONDecodeError:
                print(f"✗ Error leyendo archivo de firma: {sig_file} (formato inválido)")
                invalid_signatures += 1
            except Exception as e:
                print(f"✗ Error procesando archivo {sig_file}: {e}")
                invalid_signatures += 1
        
        print("-" * 50)
        print(f"✅ Firmas válidas: {valid_signatures}")
        print(f"❌ Firmas inválidas: {invalid_signatures}")
        print(f"📊 Total de firmas verificadas: {num_firmas}")
        
        if valid_signatures == num_firmas:
            print("\n🎉 ¡TODAS las firmas son válidas!")
            return True
        else:
            print(f"\n⚠️  Solo {valid_signatures} de {num_firmas} firmas son válidas.")
            return False
    
    def collect_signatures_interactive(self):        
        while True:
            try:
                num_firmas = int(input("\n¿Cuántas firmas deseas recoger? "))
                if num_firmas > 0:
                    break
                else:
                    print("Por favor, ingresa un número mayor que 0.")
            except ValueError:
                print("Por favor, ingresa un número válido.")
        
        signature_files = []
        for i in range(num_firmas):
            while True:
                nombre_archivo = input(f"\nIngresa el nombre del archivo de firma #{i+1}: ").strip()
                if nombre_archivo:
                    # Agregar extensión .json si no la tiene
                    if not nombre_archivo.endswith('.json'):
                        nombre_archivo += '.json'
                    signature_files.append(nombre_archivo)
                    break
                else:
                    print("El nombre no puede estar vacío.")
        
        return self.collect_signatures(signature_files)
    
    def save_signature_package(self, signature_package, output_path=None):
        if output_path is None:
            output_path = f"firma_{self.user_id}.json"
        
        with open(output_path, 'w') as f:
            json.dump(signature_package, f, indent=2)
        
        return output_path
    
    def collect_signatures(self, signature_files, output_file="todas_las_firmas.json"):
        all_signatures = {'signatures': []}
        
        print(f"\nRecolectando {len(signature_files)} firmas...")
        
        for sig_file in signature_files:
            try:
                with open(sig_file, 'r') as f:
                    signature_data = json.load(f)
                all_signatures['signatures'].append(signature_data)
                print(f"✓ Firma de {signature_data['user_id']} añadida desde {sig_file}")
            except FileNotFoundError:
                print(f"✗ Archivo no encontrado: {sig_file}")
            except json.JSONDecodeError:
                print(f"✗ Error de formato en: {sig_file}")
            except Exception as e:
                print(f"✗ Error cargando {sig_file}: {e}")
        
        with open(output_file, 'w') as f:
            json.dump(all_signatures, f, indent=2)
        
        print(f"\n📁 Todas las firmas guardadas en: {output_file}")
        return output_file
    
    def get_timestamp(self):
        """Obtiene timestamp actual"""
        import time
        return time.time()
    
    def save_public_keys_to_file(self, filename="public_keys.json"):
        data = {
            'user_id': self.user_id,
            'public_key': self.get_public_key_pem(),
            'team_public_keys': {
                member_id: key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
                for member_id, key in self.team_public_keys.items()
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
    
    def load_public_keys_from_file(self, filename="public_keys.json"):
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
            
            if data.get('public_key'):
                self.public_key = serialization.load_pem_public_key(
                    data['public_key'].encode('utf-8'),
                    backend=default_backend()
                )
            
            self.team_public_keys = {}
            for member_id, key_pem in data.get('team_public_keys', {}).items():
                self.team_public_keys[member_id] = serialization.load_pem_public_key(
                    key_pem.encode('utf-8'),
                    backend=default_backend()
                )
            
            self.user_id = data.get('user_id')
            return True
        except FileNotFoundError:
            return False


def registrar_llaves_publicas(plataforma):
    print("\n--- REGISTRO DE LLAVES PÚBLICAS ---")
    
    while True:
        try:
            num_usuarios = int(input("\n¿Cuántos usuarios deseas registrar? "))
            if num_usuarios > 0:
                break
            else:
                print("Por favor, ingresa un número mayor que 0.")
        except ValueError:
            print("Por favor, ingresa un número válido.")
    
    for i in range(num_usuarios):
        print(f"\nUsuario #{i+1}:")
        user_id = input("ID del usuario: ").strip()
        public_key_file = input("Archivo de llave pública (.pem): ").strip()
        
        if not public_key_file.endswith('.pem'):
            public_key_file += '.pem'
        
        try:
            with open(public_key_file, 'r') as f:
                public_key_pem = f.read()
            
            if plataforma.add_team_member_public_key(user_id, public_key_pem):
                print(f"✓ Llave pública de {user_id} registrada correctamente")
            else:
                print(f"✗ Error registrando llave de {user_id}")
        except FileNotFoundError:
            print(f"✗ Archivo no encontrado: {public_key_file}")
    
    plataforma.save_public_keys_to_file("public_keys.json")
    print("\n✓ Todas las llaves públicas guardadas en public_keys.json")

def verificar_firmas(plataforma):
    print("\n--- VERIFICACIÓN DE FIRMAS ---")
    
    documento = input("Ruta del documento a verificar: ").strip()
    
    if not os.path.exists(documento):
        print("✗ El documento no existe.")
        return
    
    # Verificación interactiva
    plataforma.verify_signatures_interactive(documento)

def recolectar_firmas(plataforma):
    print("\n--- COLECCIÓN DE FIRMAS ---")
    
    archivo_salida = input("Nombre del archivo de salida (default: todas_las_firmas.json): ").strip()
    if not archivo_salida:
        archivo_salida = "todas_las_firmas.json"
    
    if not archivo_salida.endswith('.json'):
        archivo_salida += '.json'
    
    # Colección interactiva
    plataforma.collect_signatures_interactive()

if __name__ == "__main__":
    pass