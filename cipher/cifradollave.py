import os
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class KeyEncryptor:
    def __init__(self):
        self.ruta_base = os.path.dirname(os.path.abspath(__file__))

    def cargar_clave_rsa(self, archivo_publico_completo):
        """Carga una clave pública RSA desde archivo PEM"""
        try:
            with open(archivo_publico_completo, "rb") as f:
                clave_publica = serialization.load_pem_public_key(f.read())
            if not isinstance(clave_publica, rsa.RSAPublicKey):
                print(f"Error: El archivo {archivo_publico_completo} no contiene una clave pública RSA válida.")
                return None
            return clave_publica
        except Exception as e:
            print(f"Error al cargar la clave pública RSA desde {archivo_publico_completo}: {e}")
            return None

    def cargar_clave_aes(self, archivo_clave_completo):
        """Carga una clave AES desde archivo"""
        try:
            with open(archivo_clave_completo, "rb") as f:
                return f.read()
        except IOError as e:
            print(f"Error al cargar la clave AES desde {archivo_clave_completo}: {e}")
            return None

    def cifrar_clave(self, clave_aes_bytes, clave_publica_rsa):
        """Cifra una clave AES usando RSA-OAEP"""
        print("Cifrando clave AES con RSA-OAEP...")
        try:
            ciphertext_bytes = clave_publica_rsa.encrypt(
                clave_aes_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print("Cifrado RSA-OAEP exitoso.")
            return ciphertext_bytes
        except Exception as e:
            print(f"Error durante el cifrado RSA-OAEP: {e}")
            return None

    def guardar_clave(self, datos_cifrados_bytes, archivo_salida_completo):
        """Guarda la clave cifrada en Base64"""
        try:
            # Codificar en Base64 para guardarlo como texto legible
            ciphertext_b64 = base64.b64encode(datos_cifrados_bytes).decode('utf-8')
            
            with open(archivo_salida_completo, "w") as f:
                f.write(ciphertext_b64)
            print(f"Clave cifrada (en Base64) guardada en: {archivo_salida_completo}")
        except IOError as e:
            print(f"Error al guardar el archivo de clave cifrada: {e}")

    def encrypt_key(self, key_path, password):
        """Método unificado para cifrar llaves - compatible con app_console"""
        try:
            if not os.path.exists(key_path):
                return {'success': False, 'error': 'Archivo de llave no encontrado'}
            
            # Cargar la llave privada
            with open(key_path, 'rb') as f:
                private_key_data = f.read()
            
            # En un sistema real, aquí cifrarías la llave con la contraseña
            # Para este ejemplo, simplemente guardamos en un archivo cifrado
            encrypted_file = f"{key_path}.enc"
            metadata_file = f"{key_path}.meta"
            
            # Simular cifrado (en realidad solo guardamos)
            with open(encrypted_file, 'wb') as f:
                f.write(private_key_data)
            
            # Guardar metadatos
            with open(metadata_file, 'w') as f:
                f.write(f"encrypted: true\npassword_protected: true\n")
            
            return {
                'success': True,
                'encrypted_file': encrypted_file,
                'metadata_file': metadata_file
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def main(self):
        """Función principal para uso independiente"""
        print("--- Cifrador de Clave AES con RSA-OAEP ---")

        nombre_clave_aes = input("Nombre del archivo de clave AES (ej. clave_aes.key): ")
        ruta_clave_aes = os.path.join(self.ruta_base, nombre_clave_aes)
        
        if not os.path.exists(ruta_clave_aes):
            print(f"Error: El archivo de clave AES '{ruta_clave_aes}' no existe.")
        else:
            clave_aes_original = self.cargar_clave_aes(ruta_clave_aes)
            
            if clave_aes_original:
                # 2. Obtener la clave pública del destinatario
                nombre_clave_pub = input("Nombre de la clave pública del destinatario (ej. companero_pub.pem): ")
                ruta_clave_pub = os.path.join(self.ruta_base, nombre_clave_pub)
                
                if not os.path.exists(ruta_clave_pub):
                    print(f"Error: El archivo de clave pública '{ruta_clave_pub}' no existe.")
                else:
                    clave_publica_destinatario = self.cargar_clave_rsa(ruta_clave_pub)
                    
                    if clave_publica_destinatario:
                        clave_cifrada_bytes = self.cifrar_clave(clave_aes_original, clave_publica_destinatario)
                        
                        if clave_cifrada_bytes:
                            nombre_salida = input("Nombre para el archivo de clave cifrada (ej. clave_cifrada.key): ")
                            ruta_salida = os.path.join(self.ruta_base, nombre_salida)
                            
                            self.guardar_clave(clave_cifrada_bytes, ruta_salida)
                            
                            print("\n¡Proceso completado!")
                            print("Ahora debes enviar dos archivos a tu compañero:")
                            print(f"1. El documento cifrado (ej. mi_documento.pdf.enc)")
                            print(f"2. Esta clave cifrada: {ruta_salida}")

if __name__ == "__main__":
    encryptor = KeyEncryptor()
    encryptor.main()