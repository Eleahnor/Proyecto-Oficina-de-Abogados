import os
from cryptography.fernet import Fernet, InvalidToken

class DocumentDecryptor:
    def __init__(self):
        self.ruta_base = os.path.dirname(os.path.abspath(__file__))

    def cargar_clave_aes(self, archivo_clave_completo):
        """Carga la clave AES desde un archivo"""
        try:
            with open(archivo_clave_completo, "rb") as f:
                return f.read()
        except IOError as e:
            print(f"Error al cargar la clave desde {archivo_clave_completo}: {e}")
            return None

    def descifrar_archivo(self, archivo_entrada_cifrado_completo, archivo_salida_descifrado_completo, clave):
        """Descifra un archivo usando Fernet"""
        f = Fernet(clave)
        try:
            with open(archivo_entrada_cifrado_completo, "rb") as file_in:
                datos_cifrados = file_in.read()
                
            datos_descifrados = f.decrypt(datos_cifrados)
            
            with open(archivo_salida_descifrado_completo, "wb") as file_out:
                file_out.write(datos_descifrados)
                
            print(f"Archivo descifrado exitosamente en: {archivo_salida_descifrado_completo}")
            return True
            
        except InvalidToken:
            print("ERROR CRÍTICO: La clave es incorrecta o el archivo ha sido manipulado.")
            return False
        except Exception as e:
            print(f"Error inesperado: {e}")
            return False

    def decrypt_document(self, encrypted_path, metadata_path, password):
        """Método unificado para descifrar documentos - compatible con app_console"""
        try:
            # Para compatibilidad con el sistema principal
            # En este caso simple, usamos la contraseña directamente
            clave = Fernet.generate_key()  # Esto no es seguro, solo para demo
            # En un sistema real, deberías derivar una clave de la contraseña
            
            if not os.path.exists(encrypted_path):
                return {'success': False, 'error': 'Archivo cifrado no encontrado'}
            
            # Generar nombre de salida
            output_path = f"decrypted_{os.path.basename(encrypted_path).replace('.enc', '')}"
            
            result = self.descifrar_archivo(encrypted_path, output_path, clave)
            
            if result:
                return {
                    'success': True,
                    'decrypted_path': output_path,
                    'original_filename': os.path.basename(encrypted_path).replace('.enc', '')
                }
            else:
                return {'success': False, 'error': 'Error en el descifrado'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def main(self):
        """Función principal para uso independiente"""
        print("\n" + "=" * 40)
        print("   PANEL ABOGADO: Descifrar Documento")
        print("=" * 40)
        
        archivo_in = input("Nombre del archivo cifrado (ej. reporte.pdf.enc): ")
        archivo_out = input("Nombre para guardar descifrado (ej. reporte_final.pdf): ")
        archivo_clave = input("Nombre de la clave AES recuperada (ej. clave_aes.key): ")

        ruta_in = os.path.join(self.ruta_base, archivo_in)
        ruta_out = os.path.join(self.ruta_base, archivo_out)
        ruta_clave = os.path.join(self.ruta_base, archivo_clave)
        
        if os.path.exists(ruta_in) and os.path.exists(ruta_clave):
            clave = self.cargar_clave_aes(ruta_clave)
            if clave:
                self.descifrar_archivo(ruta_in, ruta_out, clave)
        else:
            print("Error: Falta el archivo cifrado o la clave.")

        input("\nPresiona Enter para salir...")

if __name__ == "__main__":
    decryptor = DocumentDecryptor()
    decryptor.main()