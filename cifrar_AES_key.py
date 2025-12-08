from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os

class KeyEncryptor:
    """Cifra contraseñas/llaves usando RSA"""
    
    def encrypt_key_for_member(self, password_file, member_id, key_generator):
        """
        Cifra una contraseña/llave para un miembro específico del equipo
        
        Args:
            password_file: Archivo con la contraseña en texto plano
            member_id: ID del miembro del equipo
            key_generator: Instancia de KeyGenerator con llaves públicas del equipo
        
        Returns:
            dict con 'success', 'encrypted_file' o 'error'
        """
        try:
            # Verificar que el miembro existe en el equipo
            if member_id not in key_generator.team_public_keys:
                return {
                    'success': False,
                    'error': f'Miembro {member_id} no encontrado en el equipo'
                }
            
            # Leer la contraseña
            with open(password_file, 'r') as f:
                password_text = f.read().strip()
            
            # Obtener la llave pública del miembro
            public_key = key_generator.team_public_keys[member_id]
            
            # Cifrar la contraseña con la llave pública del miembro
            encrypted_password = public_key.encrypt(
                password_text.encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Guardar la contraseña cifrada
            output_file = os.path.join('encrypted', f'contraseña_{member_id}.pem')
            with open(output_file, 'wb') as f:
                f.write(encrypted_password)
            
            return {
                'success': True,
                'encrypted_file': output_file,
                'member_id': member_id
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def encrypt_key(self, key_file, password):
        """
        Cifra una llave privada con una contraseña (método original)
        """
        try:
            # Implementación del método original si lo necesitas
            pass
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }