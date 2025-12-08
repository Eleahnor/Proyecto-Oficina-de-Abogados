import os
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class DocumentDecryptor:
    def __init__(self):
        pass

    # --- UTILIDAD PARA LIMPIAR NOMBRES ---
    def _generar_nombre_salida(self, encrypted_path):
        """
        Toma una ruta como 'encrypted_doc1.pdf.enc'
        y devuelve una ruta limpia como 'decrypted_doc1.pdf'
        """
        directory = os.path.dirname(encrypted_path)
        filename = os.path.basename(encrypted_path)
        
        # 1. Quitar extensión .enc
        if filename.endswith('.enc'):
            filename = filename[:-4]
            
        # 2. Quitar prefijo encrypted_
        if filename.startswith("encrypted_"):
            filename = filename.replace("encrypted_", "", 1)
            
        # 3. Agregar prefijo decrypted_
        new_filename = f"decrypted_{filename}"
        
        return os.path.join(directory, new_filename), filename

    # --- OPCIÓN 2: Descifrar con archivo de llave (.key) ---
    def decrypt_with_keyfile(self, encrypted_path, key_path):
        try:
            if not os.path.exists(encrypted_path) or not os.path.exists(key_path):
                return {'success': False, 'error': 'Faltan archivos (cifrado o llave)'}

            # Cargar la llave tal cual
            with open(key_path, 'rb') as f:
                clave = f.read()

            f = Fernet(clave)
            
            with open(encrypted_path, 'rb') as file_in:
                datos_cifrados = file_in.read()

            datos_descifrados = f.decrypt(datos_cifrados)
            
            # Generar nombre limpio
            decrypted_path, original_name = self._generar_nombre_salida(encrypted_path)

            with open(decrypted_path, 'wb') as file_out:
                file_out.write(datos_descifrados)

            return {
                'success': True, 
                'decrypted_path': decrypted_path,
                'original_filename': original_name
            }
            
        except InvalidToken:
            return {'success': False, 'error': 'La llave no es correcta para este archivo'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # --- OPCIÓN 4: Descifrar con Password de Equipo ---
    def derivar_clave_desde_password(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        clave = kdf.derive(password.encode())
        return base64.urlsafe_b64encode(clave)

    def decrypt_document(self, encrypted_path, metadata_path, password):
        try:
            # Validaciones
            if not os.path.exists(encrypted_path):
                return {'success': False, 'error': f'No existe archivo cifrado: {encrypted_path}'}
            if not os.path.exists(metadata_path):
                return {'success': False, 'error': f'No existe archivo metadata: {metadata_path}'}

            # Leer salt
            with open(metadata_path, 'rb') as f:
                salt = f.read()

            # Regenerar clave
            clave = self.derivar_clave_desde_password(password, salt)
            f = Fernet(clave)

            # Leer datos
            with open(encrypted_path, 'rb') as file_in:
                datos_cifrados = file_in.read()

            # Descifrar
            datos_descifrados = f.decrypt(datos_cifrados)
            
            # --- CORRECCIÓN AQUÍ: Usar la misma lógica de nombres limpios ---
            decrypted_path, original_name = self._generar_nombre_salida(encrypted_path)

            # Guardar
            with open(decrypted_path, 'wb') as out:
                out.write(datos_descifrados)

            return {
                'success': True,
                'decrypted_path': decrypted_path,
                'original_filename': original_name
            }

        except InvalidToken:
            return {'success': False, 'error': 'Contraseña incorrecta'}
        except Exception as e:
            return {'success': False, 'error': str(e)}