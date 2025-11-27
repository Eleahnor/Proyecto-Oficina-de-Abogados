import os
from cryptography.fernet import Fernet, InvalidToken

ruta_base = os.path.dirname(os.path.abspath(__file__))

def cargar_clave_aes(archivo_clave_completo):
    try:
        with open(archivo_clave_completo, "rb") as f:
            return f.read()
    except IOError as e:
        print(f"Error al cargar la clave desde {archivo_clave_completo}: {e}")
        return None

def descifrar_archivo(archivo_entrada_cifrado_completo, archivo_salida_descifrado_completo, clave):
    f = Fernet(clave)
    try:
        with open(archivo_entrada_cifrado_completo, "rb") as file_in:
            datos_cifrados = file_in.read()
            
        datos_descifrados = f.decrypt(datos_cifrados)
        
        with open(archivo_salida_descifrado_completo, "wb") as file_out:
            file_out.write(datos_descifrados)
            
        print(f"Archivo descifrado exitosamente en: {archivo_salida_descifrado_completo}")
        
    except InvalidToken:
        print("ERROR CRÍTICO: La clave es incorrecta o el archivo ha sido manipulado.")
    except Exception as e:
        print(f"Error inesperado: {e}")

def main():
    print("\n" + "=" * 40)
    print("   PANEL ABOGADO: Descifrar Documento")
    print("=" * 40)
    
    archivo_in = input("Nombre del archivo cifrado (ej. reporte.pdf.enc): ")
    archivo_out = input("Nombre para guardar descifrado (ej. reporte_final.pdf): ")
    archivo_clave = input("Nombre de la clave AES recuperada (ej. clave_aes.key): ")

    ruta_in = os.path.join(ruta_base, archivo_in)
    ruta_out = os.path.join(ruta_base, archivo_out)
    ruta_clave = os.path.join(ruta_base, archivo_clave)
    
    if os.path.exists(ruta_in) and os.path.exists(ruta_clave):
        clave = cargar_clave_aes(ruta_clave)
        if clave:
            descifrar_archivo(ruta_in, ruta_out, clave)
    else:
        print("Error: Falta el archivo cifrado o la clave.")

    input("\nPresiona Enter para salir...")

if __name__ == "__main__":
    main()