import os
from cryptography.fernet import Fernet

ruta_base = os.path.dirname(os.path.abspath(__file__))

def generar_clave_aes():
    return Fernet.generate_key()

def guardar_clave_aes(clave, archivo_salida_completo):
    try:
        with open(archivo_salida_completo, "wb") as f:
            f.write(clave)
        print(f"Clave AES guardada exitosamente en: {archivo_salida_completo}")
    except IOError as e:
        print(f"Error al guardar la clave en {archivo_salida_completo}: {e}")

def cargar_clave_aes(archivo_clave_completo):
    try:
        with open(archivo_clave_completo, "rb") as f:
            return f.read()
    except IOError as e:
        print(f"Error al cargar la clave desde {archivo_clave_completo}: {e}")
        return None

def cifrar_archivo(plaintext, cifrado, clave):
    f = Fernet(clave)
    try:
        with open(plaintext, "rb") as file_in:
            datos_originales = file_in.read()
        
        datos_cifrados = f.encrypt(datos_originales)
        
        with open(cifrado, "wb") as file_out:
            file_out.write(datos_cifrados)
            
        print(f"Archivo '{plaintext}' cifrado exitosamente en: {cifrado}")
    except Exception as e:
        print(f"Error durante el cifrado: {e}")

def main():
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
            ruta_clave = os.path.join(ruta_base, nombre_clave)
            clave_nueva = generar_clave_aes()
            guardar_clave_aes(clave_nueva, ruta_clave)

        elif opcion == '2':
            archivo_in = input("Archivo a cifrar (ej. reporte.pdf): ")
            archivo_out = input("Nombre salida cifrado (ej. reporte.pdf.enc): ")
            archivo_clave = input("Nombre de la clave a usar (ej. clave_aes.key): ")

            ruta_in = os.path.join(ruta_base, archivo_in)
            ruta_out = os.path.join(ruta_base, archivo_out)
            ruta_clave = os.path.join(ruta_base, archivo_clave)

            if os.path.exists(ruta_in) and os.path.exists(ruta_clave):
                clave = cargar_clave_aes(ruta_clave)
                if clave:
                    cifrar_archivo(ruta_in, ruta_out, clave)
            else:
                print("Error: No se encuentra el archivo de entrada o la clave.")

        elif opcion == '3':
            break

if __name__ == "__main__":
    main()