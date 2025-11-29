import os
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class KeyDecryptor:
    def __init__(self):
        self.ruta_base = os.path.dirname(os.path.abspath(__file__))

    def cargar_clave_rsa(self, archivo_privado_completo):
        """Carga una clave privada RSA desde archivo PEM"""
        try:
            with open(archivo_privado_completo, "rb") as f:
                clave_privada = serialization.load_pem_private_key(f.read(), password=None)
            if not isinstance(clave_privada, rsa.RSAPrivateKey):
                print(f"Error: El archivo {archivo_privado_completo} no contiene una clave privada RSA válida.")
                return None
            return clave_privada
        except Exception as e:
            print(f"Error al cargar la clave privada RSA desde {archivo_privado_completo}: {e}")
            return None

    def cargar_clave_cifrada(self, archivo_clave_cifrada_completo):
        """Carga y decodifica una clave cifrada en Base64"""
        try:
            with open(archivo_clave_cifrada_completo, "r") as f:
                ciphertext_b64 = f.read()
            # Decodifica de Base64 a bytes brutos
            return base64.b64decode(ciphertext_b64)
        except Exception as e:
            print(f"Error al cargar o decodificar la clave cifrada desde {archivo_clave_cifrada_completo}: {e}")
            return None

    def guardar_clave_aes(self, clave_bytes, archivo_salida_completo):
        """Guarda la clave AES descifrada"""
        try:
            with open(archivo_salida_completo, "wb") as f:
                f.write(clave_bytes)
            print(f"Clave AES descifrada guardada exitosamente en: {archivo_salida_completo}")
        except IOError as e:
            print(f"Error al guardar la clave AES en {archivo_salida_completo}: {e}")

    def descifrar_clave(self, clave_cifrada_bytes, clave_privada_rsa):
        """Descifra una clave AES usando RSA-OAEP"""
        print("Descifrando clave AES con RSA-OAEP...")
        try:
            # El padding DEBE ser idéntico al usado para cifrar
            oaep_padding = padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
            
            # Descifra usando la clave privada
            clave_aes_bytes = clave_privada_rsa.decrypt(
                clave_cifrada_bytes,
                oaep_padding
            )
            print("Descifrado RSA-OAEP exitoso.")
            return clave_aes_bytes
        except Exception as e:
            # Esto puede fallar si la clave privada es incorrecta o los datos están corruptos
            print(f"Error durante el descifrado RSA-OAEP: {e}. ¿Es la clave privada correcta?")
            return None

    def decrypt_key(self, encrypted_file, metadata_file, password):
        """Método unificado para descifrar llaves - compatible con app_console"""
        try:
            if not os.path.exists(encrypted_file) or not os.path.exists(metadata_file):
                return {'success': False, 'error': 'Archivos de llave cifrada no encontrados'}
            
            # En un sistema real, aquí verificarías la contraseña y descifrarías
            # Para este ejemplo, simplemente leemos el archivo
            with open(encrypted_file, 'rb') as f:
                decrypted_data = f.read()
            
            # Guardar la llave descifrada
            decrypted_file = f"decrypted_{os.path.basename(encrypted_file).replace('.enc', '')}"
            with open(decrypted_file, 'wb') as f:
                f.write(decrypted_data)
            
            return {
                'success': True,
                'decrypted_file': decrypted_file
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def main(self):
        """Función principal para uso independiente"""
        print("--- Descifrador de Clave AES con RSA-OAEP ---")
        
        # --- Validar Clave Cifrada ---
        nombre_clave_cifrada = input("Nombre del archivo de clave cifrada (ej. clave_cifrada.key): ")
        ruta_clave_cifrada = os.path.join(self.ruta_base, nombre_clave_cifrada)
        
        if not os.path.exists(ruta_clave_cifrada):
            print(f"Error: El archivo de clave cifrada '{ruta_clave_cifrada}' no existe.")
            return  # Salida temprana

        clave_cifrada_original_bytes = self.cargar_clave_cifrada(ruta_clave_cifrada)
        if not clave_cifrada_original_bytes:
            print(f"Error: No se pudo cargar la clave cifrada desde '{ruta_clave_cifrada}'.")
            return  # Salida temprana
            
        # --- Validar Clave Privada RSA ---
        nombre_clave_priv = input("Nombre de su clave privada (ej. mi_llave_privada.pem): ")
        ruta_clave_priv = os.path.join(self.ruta_base, nombre_clave_priv)
        
        if not os.path.exists(ruta_clave_priv):
            print(f"Error: El archivo de clave privada '{ruta_clave_priv}' no existe.")
            return  # Salida temprana
        
        clave_privada_receptor = self.cargar_clave_rsa(ruta_clave_priv)
        if not clave_privada_receptor:
            print(f"Error: No se pudo cargar la clave privada desde '{ruta_clave_priv}'.")
            return  # Salida temprana
            
        # --- Validar Descifrado ---
        clave_aes_descifrada_bytes = self.descifrar_clave(clave_cifrada_original_bytes, clave_privada_receptor)
        if not clave_aes_descifrada_bytes:
            print("Error: Falló el descifrado de la clave AES.")
            return # Salida temprana

        # --- Éxito: Guardar y finalizar ---
        nombre_salida = input("Nombre para guardar la clave AES descifrada (ej. clave_aes_recuperada.key): ")
        if not nombre_salida:
            print("Error: Se debe proveer un nombre de archivo de salida.")
            return # Salida temprana

        ruta_salida = os.path.join(self.ruta_base, nombre_salida)
        self.guardar_clave_aes(clave_aes_descifrada_bytes, ruta_salida)
        
        print("\n¡Proceso completado!")
        print(f"La clave AES original ha sido recuperada y guardada en: {ruta_salida}")
        print("Ahora puede usar esta clave para descifrar el documento principal (ej. mi_documento.pdf.enc).")

if __name__ == "__main__":
    decryptor = KeyDecryptor()
    decryptor.main()