import os
import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

class KeyExchangeSystem:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.team_public_keys = {}
        self.symmetric_keys = {}
        
    def generate_key_pair(self):
        """Genera un par de llaves RSA"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
    def get_public_key_pem(self):
        """Devuelve la llave pública en formato PEM"""
        if self.public_key:
            return self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
        return None
    
    def add_team_member_public_key(self, member_id, public_key_pem):
        """Agrega la llave pública de un miembro del equipo"""
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
    
    def encrypt_symmetric_key(self, member_id, symmetric_key):
        """Encripta una llave simétrica con la llave pública del miembro"""
        if member_id not in self.team_public_keys:
            raise ValueError(f"Llave pública no encontrada para {member_id}")
        
        encrypted_key = self.team_public_keys[member_id].encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted_key).decode('utf-8')
    
    def decrypt_symmetric_key(self, encrypted_key_b64):
        """Desencripta una llave simétrica con la llave privada"""
        if not self.private_key:
            raise ValueError("No hay llave privada disponible")
        
        encrypted_key = base64.b64decode(encrypted_key_b64)
        symmetric_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return symmetric_key
    
    def generate_symmetric_key(self):
        """Genera una llave simétrica para AES"""
        return Fernet.generate_key()
    
    def save_keys_to_file(self, filename="keys.json"):
        """Guarda las llaves en un archivo JSON"""
        data = {
            'private_key': self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8') if self.private_key else None,
            'public_key': self.get_public_key_pem(),
            'team_public_keys': {
                member_id: key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
                for member_id, key in self.team_public_keys.items()
            },
            'symmetric_keys': self.symmetric_keys
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
    
    def load_keys_from_file(self, filename="keys.json"):
        """Carga las llaves desde un archivo JSON"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
            
            if data.get('private_key'):
                self.private_key = serialization.load_pem_private_key(
                    data['private_key'].encode('utf-8'),
                    password=None,
                    backend=default_backend()
                )
            
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
            
            self.symmetric_keys = data.get('symmetric_keys', {})
            return True
        except FileNotFoundError:
            return False