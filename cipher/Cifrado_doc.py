import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class DocumentEncryptor:
    def __init__(self):
        self.ruta_base = os.path.dirname(os.path.abspath(__file__))

    # --- TUS MÉTODOS EXISTENTES (HERRAMIENTAS) ---
    def generar_clave_aes(self):
        return Fernet.generate_key()

    def guardar_clave_aes(self, clave, archivo_salida_completo):
        try:
            with open(archivo_salida_completo, "wb") as f:
                f.write(clave)
            return True
        except IOError as e:
            print(f"Error al guardar la clave: {e}")
            return False

    def cifrar_archivo(self, plaintext, cifrado, clave):
        f = Fernet(clave)
        try:
            with open(plaintext, "rb") as file_in:
                datos_originales = file_in.read()
            
            datos_cifrados = f.encrypt(datos_originales)
            
            with open(cifrado, "wb") as file_out:
                file_out.write(datos_cifrados)
            return True
        except Exception as e:
            print(f"Error durante el cifrado: {e}")
            return False

    def derivar_clave_desde_password(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        clave = kdf.derive(password.encode())
        return base64.urlsafe_b64encode(clave)

    # --- NUEVO MÉTODO PARA APP_CONSOLE (OPCIÓN 1) ---
    def encrypt_with_generated_key(self, document_path):
        """
        Genera una llave automática, cifra y devuelve las rutas.
        Usa las herramientas que ya tenías creadas.
        """
        try:
            if not os.path.exists(document_path):
                return {'success': False, 'error': 'Archivo no encontrado'}

            # 1. Generar nueva llave
            clave = self.generar_clave_aes()
            
            # 2. Definir nombres de archivo
            filename = os.path.basename(document_path)
            encrypted_path = f"encrypted_{filename}.enc"
            key_path = f"key_{filename}.key"
            
            # Asegurar rutas absolutas (opcional, pero recomendado)
            directory = os.path.dirname(document_path)
            full_encrypted_path = os.path.join(directory, encrypted_path)
            full_key_path = os.path.join(directory, key_path)

            # 3. Usar tus métodos existentes para guardar y cifrar
            if self.guardar_clave_aes(clave, full_key_path):
                if self.cifrar_archivo(document_path, full_encrypted_path, clave):
                    return {
                        'success': True,
                        'encrypted_path': full_encrypted_path,
                        'key_path': full_key_path
                    }
            
            return {'success': False, 'error': 'Fallo al guardar archivos'}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    # --- MÉTODO PARA EQUIPO (OPCIÓN 3 - Mantiene Password) ---
    def encrypt_document(self, document_path, password, output_path=None):
        try:
            if not os.path.exists(document_path):
                return {'success': False, 'error': 'Archivo no encontrado'}
            
            salt = os.urandom(16)
            clave = self.derivar_clave_desde_password(password, salt)
            
            if output_path is None:
                output_path = f"encrypted_{os.path.basename(document_path)}.enc"
            
            metadata_path = output_path + '.meta'
            
            if self.cifrar_archivo(document_path, output_path, clave):
                with open(metadata_path, 'wb') as f:
                    f.write(salt)
                return {
                    'success': True, 
                    'encrypted_path': output_path, 
                    'metadata_path': metadata_path
                }
            return {'success': False, 'error': 'Error en el cifrado'}
        except Exception as e:
            return {'success': False, 'error': str(e)}