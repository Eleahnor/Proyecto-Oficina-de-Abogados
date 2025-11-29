import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class DocumentEncryptor:
    def __init__(self):
        self.ruta_base = os.path.dirname(os.path.abspath(__file__))

    def generar_clave_aes(self):
        """Genera una nueva clave AES"""
        return Fernet.generate_key()

    def derivar_clave_desde_password(self, password, salt):
        """Deriva una clave AES desde una contraseña usando PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        clave = kdf.derive(password.encode())
        return base64.urlsafe_b64encode(clave)

    def guardar_clave_aes(self, clave, archivo_salida_completo):
        """Guarda la clave AES en un archivo"""
        try:
            with open(archivo_salida_completo, "wb") as f:
                f.write(clave)
            print(f"Clave AES guardada exitosamente en: {archivo_salida_completo}")
        except IOError as e:
            print(f"Error al guardar la clave en {archivo_salida_completo}: {e}")

    def cargar_clave_aes(self, archivo_clave_completo):
        """Carga la clave AES desde un archivo"""
        try:
            with open(archivo_clave_completo, "rb") as f:
                return f.read()
        except IOError as e:
            print(f"Error al cargar la clave desde {archivo_clave_completo}: {e}")
            return None

    def cifrar_archivo(self, plaintext, cifrado, clave):
        """Cifra un archivo usando Fernet"""
        f = Fernet(clave)
        try:
            with open(plaintext, "rb") as file_in:
                datos_originales = file_in.read()
            
            datos_cifrados = f.encrypt(datos_originales)
            
            with open(cifrado, "wb") as file_out:
                file_out.write(datos_cifrados)
                
            print(f"Archivo '{plaintext}' cifrado exitosamente en: {cifrado}")
            return True
        except Exception as e:
            print(f"Error durante el cifrado: {e}")
            return False

    def encrypt_document(self, document_path, password, output_path=None):
        """Método unificado para cifrar documentos - compatible con app_console"""
        try:
            if not os.path.exists(document_path):
                return {'success': False, 'error': 'Archivo no encontrado'}
            
            # Generar salt y derivar clave desde password
            salt = os.urandom(16)
            clave = self.derivar_clave_desde_password(password, salt)
            
            # Generar nombres de archivo
            if output_path is None:
                output_path = f"encrypted_{os.path.basename(document_path)}.enc"
            
            metadata_path = output_path + '.meta'
            
            # Cifrar archivo
            result = self.cifrar_archivo(document_path, output_path, clave)
            
            if result:
                # Guardar metadatos (salt)
                with open(metadata_path, 'wb') as f:
                    f.write(salt)
                
                return {
                    'success': True,
                    'encrypted_path': output_path,
                    'metadata_path': metadata_path
                }
            else:
                return {'success': False, 'error': 'Error en el cifrado'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def main(self):
        """Función principal para uso independiente"""
        while True:
            print("\n" + "=" * 40)
            print("   PANEL DIRECTOR: Generar y Cifrar")
            print("=" * 40)
            print("1. Generar nueva clave AES")
            print("2. Cifrar un archivo")
            print("3. Salir")
            print("-" * 40)
            opcion = input("Seleccione una opción: ").strip()

            if opcion == '1':
                nombre_clave = input("Nombre para el archivo de clave (ej. clave_aes.key): ")
                ruta_clave = os.path.join(self.ruta_base, nombre_clave)
                clave_nueva = self.generar_clave_aes()
                self.guardar_clave_aes(clave_nueva, ruta_clave)

            elif opcion == '2':
                archivo_in = input("Archivo a cifrar (ej. reporte.pdf): ")
                archivo_out = input("Nombre salida cifrado (ej. reporte.pdf.enc): ")
                archivo_clave = input("Nombre de la clave a usar (ej. clave_aes.key): ")

                ruta_in = os.path.join(self.ruta_base, archivo_in)
                ruta_out = os.path.join(self.ruta_base, archivo_out)
                ruta_clave = os.path.join(self.ruta_base, archivo_clave)

                if os.path.exists(ruta_in) and os.path.exists(ruta_clave):
                    clave = self.cargar_clave_aes(ruta_clave)
                    if clave:
                        self.cifrar_archivo(ruta_in, ruta_out, clave)
                else:
                    print("Error: No se encuentra el archivo de entrada o la clave.")

            elif opcion == '3':
                break

if __name__ == "__main__":
    encryptor = DocumentEncryptor()
    encryptor.main()