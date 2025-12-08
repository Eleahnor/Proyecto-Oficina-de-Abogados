import os
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class KeyEncryptor:
    def __init__(self):
        pass

    def cargar_clave_rsa_publica(self, archivo_publico):
        try:
            with open(archivo_publico, "rb") as f:
                return serialization.load_pem_public_key(f.read())
        except Exception as e:
            return None

    def encrypt_aes_key_for_recipient(self, aes_key_path, recipient_public_key_path):
        """
        Cifra una llave AES (.key) usando la llave PÚBLICA (.pem) del destinatario.
        """
        try:
            if not os.path.exists(aes_key_path):
                return {'success': False, 'error': 'No existe el archivo de llave AES'}
            if not os.path.exists(recipient_public_key_path):
                return {'success': False, 'error': 'No existe la llave pública del destinatario'}

            # 1. Cargar la llave AES original (bytes)
            with open(aes_key_path, "rb") as f:
                aes_key_bytes = f.read()

            # 2. Cargar la llave pública RSA
            public_key = self.cargar_clave_rsa_publica(recipient_public_key_path)
            if not public_key:
                return {'success': False, 'error': 'Llave pública inválida'}

            # 3. Cifrar con RSA-OAEP
            ciphertext = public_key.encrypt(
                aes_key_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # 4. Guardar resultado (en Base64 para que sea manejable)
            filename = os.path.basename(aes_key_path)
            output_path = f"shared_key_for_partner.enc" # Nombre genérico, se puede mejorar
            
            # Codificamos a base64 para escribirlo como texto
            encrypted_b64 = base64.b64encode(ciphertext).decode('utf-8')
            
            with open(output_path, "w") as f:
                f.write(encrypted_b64)

            return {
                'success': True,
                'encrypted_file': output_path
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}