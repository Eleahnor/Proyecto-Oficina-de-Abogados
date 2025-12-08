from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64

class KeyDecryptor:
    """Descifra contraseñas/llaves usando RSA"""
    
    def decrypt_password(self, encrypted_file, private_key):
        """
        Descifra una contraseña que fue cifrada con la llave pública
        
        Args:
            encrypted_file: Archivo con la contraseña cifrada
            private_key: Llave privada para descifrar
        
        Returns:
            dict con 'success', 'decrypted_password' o 'error'
        """
        try:
            # Leer el archivo cifrado
            with open(encrypted_file, 'rb') as f:
                encrypted_data = f.read()
            
            # Descifrar con la llave privada
            decrypted_data = private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Convertir a texto
            decrypted_password = decrypted_data.decode('utf-8')
            
            return {
                'success': True,
                'decrypted_password': decrypted_password
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Error al descifrar: {str(e)}'
            }
    
    def decrypt_key(self, encrypted_file, metadata_file, password):
        """
        Descifra una llave privada con contraseña (método original)
        """
        try:
            # Implementación del método original si lo necesitas
            pass
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }