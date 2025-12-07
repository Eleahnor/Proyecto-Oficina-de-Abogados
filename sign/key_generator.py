import os
import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class KeyGenerator:
    def __init__(self, user_id=None):
        self.private_key = None
        self.public_key = None
        self.user_id = user_id
        self.team_public_keys = {}
    
    def generate_key_pair(self): 
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        if self.user_id:
            self.save_keys_local()
        
        return self.get_public_key_pem()
    
    def save_keys_local(self):
        if self.private_key and self.user_id:
            # Guardar llave privada
            private_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            filename = f"private_key_{self.user_id}.pem"
            with open(filename, 'wb') as f:
                f.write(private_pem)
            print(f"🔐 Llave privada guardada en: {filename}")
            
            # Guardar llave pública
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            public_filename = f"public_key_{self.user_id}.pem"
            with open(public_filename, 'wb') as f:
                f.write(public_pem)
            print(f"🔑 Llave pública guardada en: {public_filename}")
            
            return True
        return False
    
    def load_private_key(self, user_id=None):
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
            print(f"✅ Llave privada cargada para usuario: {user_id}")
            return True
        except FileNotFoundError:
            print(f"❌ Archivo de llave no encontrado: {filename}")
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
            print(f"✅ Llave pública de {member_id} agregada al equipo")
            return True
        except Exception as e:
            print(f"❌ Error cargando llave pública de {member_id}: {e}")
            return False
    
    def save_public_keys_to_file(self, filename="public_keys.json"):
        """Guarda todas las llaves públicas en un archivo"""
        data = {
            'user_id': self.user_id,
            'public_key': self.get_public_key_pem(),
            'team_public_keys': {
                member_id: key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
                for member_id, key in self.team_public_keys.items()
            },
            'timestamp': self.get_timestamp()
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"📁 Llaves públicas guardadas en: {filename}")
        return True
    
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
            print(f"✅ Llaves públicas cargadas desde: {filename}")
            return True
        except FileNotFoundError:
            print(f"❌ Archivo de llaves públicas no encontrado: {filename}")
            return False
        except Exception as e:
            print(f"❌ Error cargando llaves públicas: {e}")
            return False
    
    def get_timestamp(self):
        import time
        return time.time()

# Funciones de utilidad para gestión de llaves
def registrar_llaves_publicas_interactive():
    print("\n--- REGISTRO DE LLAVES PÚBLICAS ---")
    
    user_id = input("Tu ID de usuario: ").strip()
    key_gen = KeyGenerator(user_id)
    
    # Verificar si ya existen llaves
    if not key_gen.load_private_key():
        print("Generando nuevo par de llaves...")
        key_gen.generate_key_pair()
    
    while True:
        try:
            num_usuarios = int(input("\n¿Cuántos usuarios del equipo deseas registrar? "))
            if num_usuarios > 0:
                break
            else:
                print("Por favor, ingresa un número mayor que 0.")
        except ValueError:
            print("Por favor, ingresa un número válido.")
    
    for i in range(num_usuarios):
        print(f"\nUsuario del equipo #{i+1}:")
        team_user_id = input("ID del usuario: ").strip()
        public_key_file = input("Archivo de llave pública (.pem): ").strip()
        
        if not public_key_file.endswith('.pem'):
            public_key_file += '.pem'
        
        try:
            with open(public_key_file, 'r') as f:
                public_key_pem = f.read()
            
            if key_gen.add_team_member_public_key(team_user_id, public_key_pem):
                print(f"✅ Llave pública de {team_user_id} registrada correctamente")
            else:
                print(f"❌ Error registrando llave de {team_user_id}")
        except FileNotFoundError:
            print(f"❌ Archivo no encontrado: {public_key_file}")
    
    key_gen.save_public_keys_to_file("public_keys.json")
    print("\n🎉 Todas las llaves públicas guardadas en public_keys.json")
    return key_gen