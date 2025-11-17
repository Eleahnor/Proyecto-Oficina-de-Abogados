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

class KeyExchangeSystem:
    def __init__(self, user_id=None):
        self.private_key = None
        self.public_key = None
        self.user_id = user_id
        self.team_public_keys = {}
        self.symmetric_keys = {}
        
    def generate_key_pair(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        # Guardar llave privada localmente en archivo txt
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
            
            filename = f"private_key_{self.user_id}.txt"
            with open(filename, 'wb') as f:
                f.write(private_pem)
            print(f"✓ Llave privada guardada en: {filename}")
    
    def load_privk(self, user_id=None):
        user_id = user_id or self.user_id
        if not user_id:
            return False
            
        filename = f"private_key_{user_id}.txt"
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
    
    def encrypt_symmetric_key(self, member_id, symmetric_key):
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
        return Fernet.generate_key()
    

    # FIRMA DIGITAL 
    def create_signature(self, message):
        if not self.private_key:
            raise ValueError("No hay llave privada disponible")
        
        # Hash del mensaje
        digest = hashes.Hash(hashes.SHA256())
        digest.update(message.encode('utf-8'))
        message_hash = digest.finalize()
        
        # firmar el hash
        signature = self.private_key.sign(
            message_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return base64.b64encode(signature).decode('utf-8')
    
    def verify_signature(self, public_key_pem, message, signature_b64):
        """Verifica una firma digital"""
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            
            signature = base64.b64decode(signature_b64)
            
            # Hash del mensaje
            digest = hashes.Hash(hashes.SHA256())
            digest.update(message.encode('utf-8'))
            message_hash = digest.finalize()
            
            # Verificar firma
            public_key.verify(
                signature,
                message_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Error verificando firma: {e}")
            return False
    
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