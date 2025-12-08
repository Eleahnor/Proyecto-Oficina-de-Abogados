import os
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class KeyDecryptor:
    def __init__(self):
        pass

    def cargar_clave_rsa_privada(self, archivo_privado):
        """Intenta cargar la llave privada sin password (o implementar password si se requiere)"""
        try:
            with open(archivo_privado, "rb") as f:
                # Si tu llave privada tiene password, aquí deberías pedirlo.
                # Asumimos que no tiene password por ahora para simplificar.
                return serialization.load_pem_private_key(f.read(), password=None)
        except Exception as e:
            print(f"Error cargando privada: {e}")
            return None

    def decrypt_aes_key_with_private(self, encrypted_key_path, my_private_key_path):
        """
        Descifra una llave AES cifrada usando MI llave privada.
        """
        try:
            if not os.path.exists(encrypted_key_path):
                return {'success': False, 'error': 'No existe el archivo de llave cifrada'}
            
            # 1. Cargar la llave privada
            private_key = self.cargar_clave_rsa_privada(my_private_key_path)
            if not private_key:
                return {'success': False, 'error': 'No se pudo cargar tu llave privada'}

            # 2. Leer el archivo cifrado (Base64)
            with open(encrypted_key_path, "r") as f:
                ciphertext_b64 = f.read()
            
            ciphertext_bytes = base64.b64decode(ciphertext_b64)

            # 3. Descifrar con RSA-OAEP
            aes_key_bytes = private_key.decrypt(
                ciphertext_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # 4. Guardar la llave AES recuperada
            output_path = "recovered_aes_key.key"
            
            with open(output_path, "wb") as f:
                f.write(aes_key_bytes)

            return {
                'success': True,
                'decrypted_file': output_path
            }

        except ValueError:
            return {'success': False, 'error': 'Decryption failed. La llave privada no corresponde o el archivo está dañado.'}
        except Exception as e:
            return {'success': False, 'error': str(e)}