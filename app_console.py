import os
import base64
import json
from sign.digital_signer import DigitalSigner
from sign.signature_verifier import SignatureVerifier
from sign.key_generator import KeyGenerator
from cipher.Cifrado_doc import DocumentEncryptor
from cipher.Descifrado_doc import DocumentDecryptor
from cipher.cifradollave import KeyEncryptor
from cipher.decifradollave import KeyDecryptor
from cryptography.hazmat.primitives import serialization

class ConsoleInterface:
    def __init__(self):
        # Inicializar todos los sistemas
        self.key_gen = KeyGenerator()
        self.signer = DigitalSigner(self.key_gen)
        self.verifier = SignatureVerifier(self.key_gen)
        self.encryptor = DocumentEncryptor()
        self.decryptor = DocumentDecryptor()
        self.key_encryptor = KeyEncryptor()
        self.key_decryptor = KeyDecryptor()
        
        self.current_user = "Director"
        
        # Cargar configuración automáticamente al iniciar
        self.load_configuration()
        # Intentar cargar llave privada del usuario actual automáticamente
        self.load_current_user_private_key()
    
    def load_configuration(self):
        if os.path.exists("team_public_keys.json"):
            if self.key_gen.load_public_keys_from_file("team_public_keys.json"):
                print("✓ Configuración de equipo cargada automáticamente")
    
    def load_current_user_private_key(self):
        if self.current_user:
            if self.key_gen.load_private_key(self.current_user):
                print(f"✓ Llave privada de {self.current_user} cargada automáticamente")
            else:
                print(f"⚠️  No se pudo cargar llave privada de {self.current_user}")
                print("   Use 'Generar mis llaves' o 'Cargar mi llave privada'")
    
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_header(self):
        print("=" * 60)
        print("    SISTEMA INTEGRAL DE FIRMAS Y CIFRADO")
        print("=" * 60)
        print(f"Usuario: {self.current_user}")
        
        # Mostrar estado de las llaves en el header
        if self.key_gen.private_key:
            print("Estado: ✅ LLAVES CARGADAS - Listo para operaciones")
        else:
            print("Estado: ❌ SIN LLAVES - Configure primero")
        print()
    
    def main_menu(self):
        while True:
            self.clear_screen()
            self.print_header()
            print("1. 🔑 Gestión de Llaves")
            print("2. 📝 Operaciones de Firma Digital")
            print("3. 🔒 Operaciones de Cifrado/Descifrado")
            print("4. ⚙️  Configuración del Sistema")
            print("0. 🚪 Salir")
            print()
            
            choice = input("Seleccione una opción: ").strip()
            
            if choice == "1":
                self.keys_menu()
            elif choice == "2":
                self.signature_menu()
            elif choice == "3":
                self.encryption_menu()
            elif choice == "4":
                self.config_menu()
            elif choice == "0":
                print("Saliendo del sistema...")
                break
            else:
                input("Opción inválida. Presione Enter para continuar...")
    
    def keys_menu(self):
        while True:
            self.clear_screen()
            self.print_header()
            print("🔑 GESTIÓN DE LLAVES")
            print("1. Generar mis llaves")
            print("2. Registrar llaves públicas de equipo")
            print("3. Ver mis llaves y equipo")
            print("4. Cifrar llave privada")
            print("5. Descifrar llave privada")
            print("0. Volver al menú principal")
            print()
            
            choice = input("Seleccione una opción: ").strip()
            
            if choice == "1":
                self.generate_keys()
            elif choice == "2":
                self.register_team_keys()
            elif choice == "3":
                self.view_my_keys()
            elif choice == "4":
                self.encrypt_private_key()
            elif choice == "5":
                self.decrypt_private_key()
            elif choice == "0":
                break
            else:
                input("Opción inválida. Presione Enter para continuar...")
    
    def signature_menu(self):
        while True:
            self.clear_screen()
            self.print_header()
            print("📝 OPERACIONES DE FIRMA DIGITAL")
            print("1. Firmar documento")
            print("2. Verificar firma individual")
            print("3. Verificar múltiples firmas")
            print("4. Recolectar firmas en archivo")
            print("0. Volver al menú principal")
            print()
            
            choice = input("Seleccione una opción: ").strip()
            
            if choice == "1":
                self.sign_document()
            elif choice == "2":
                self.verify_individual_signature()
            elif choice == "3":
                self.verify_multiple_signatures()
            elif choice == "4":
                self.collect_signatures()
            elif choice == "0":
                break
            else:
                input("Opción inválida. Presione Enter para continuar...")
    
    def encryption_menu(self):
        while True:
            self.clear_screen()
            self.print_header()
            print("🔒 OPERACIONES DE CIFRADO/DESCIFRADO")
            print("1. Cifrar documento")
            print("2. Descifrar documento")
            print("3. Cifrar documento con llave de equipo")
            print("4. Descifrar documento con llave de equipo")
            print("0. Volver al menú principal")
            print()
            
            choice = input("Seleccione una opción: ").strip()
            
            if choice == "1":
                self.encrypt_document()
            elif choice == "2":
                self.decrypt_document()
            elif choice == "3":
                self.encrypt_document_team()
            elif choice == "4":
                self.decrypt_document_team()
            elif choice == "0":
                break
            else:
                input("Opción inválida. Presione Enter para continuar...")
    
    def config_menu(self):
        while True:
            self.clear_screen()
            self.print_header()
            print("⚙️  CONFIGURACIÓN DEL SISTEMA")
            print("1. Guardar configuración de equipo")
            print("2. Cargar configuración de equipo")
            print("3. Cambiar usuario")
            print("0. Volver al menú principal")
            print()
            
            choice = input("Seleccione una opción: ").strip()
            
            if choice == "1":
                filename = input("Nombre del archivo (team_public_keys.json): ").strip() or "team_public_keys.json"
                self.key_gen.save_public_keys_to_file(filename)
                print("✅ Configuración guardada")
                input("Presione Enter para continuar...")
            elif choice == "2":
                filename = input("Nombre del archivo (team_public_keys.json): ").strip() or "team_public_keys.json"
                if self.key_gen.load_public_keys_from_file(filename):
                    print("✅ Configuración cargada")
                    print(f"Miembros del equipo: {len(self.key_gen.team_public_keys)}")
                else:
                    print("❌ Archivo no encontrado")
                input("Presione Enter para continuar...")
            elif choice == "3":
                self.change_user()
            elif choice == "0":
                break
            else:
                input("Opción inválida. Presione Enter para continuar...")
    
    def generate_keys(self):
        self.clear_screen()
        self.print_header()
        print("🔑 GENERACIÓN DE LLAVES")
        
        # Preguntar si ya existen llaves
        private_key_file = f"private_key_{self.current_user}.pem"
        if os.path.exists(private_key_file):
            overwrite = input(f"⚠️  Ya existe una llave para {self.current_user}. ¿Regenerar? (s/n): ").strip().lower()
            if overwrite != 's':
                print("Operación cancelada.")
                input("\nPresione Enter para continuar...")
                return
        
        self.key_gen.user_id = self.current_user
        public_key_pem = self.key_gen.generate_key_pair()
        
        print("\n✅ Llaves generadas exitosamente:")
        print(f"   📄 Llave privada: private_key_{self.current_user}.pem")
        print(f"   📄 Llave pública: public_key_{self.current_user}.pem")
        
        # Registrar automáticamente la llave pública del usuario actual
        if self.key_gen.add_team_member_public_key(self.current_user, public_key_pem):
            print(f"✅ Llave pública de {self.current_user} registrada en equipo")
            self.key_gen.save_public_keys_to_file("team_public_keys.json")
        
        input("\nPresione Enter para continuar...")
    
    def register_team_keys(self):
        self.clear_screen()
        self.print_header()
        print("👥 REGISTRO DE LLAVES PÚBLICAS DEL EQUIPO")
        print("\nNota: Los archivos de llave pública deben estar en formato .pem")
        print("Ejemplo: public_key_Director.pem, public_key_leah.pem, etc.")
        print()
        
        try:
            num_members = int(input("¿Cuántos miembros del equipo deseas registrar? "))
        except ValueError:
            print("Número inválido")
            input("\nPresione Enter para continuar...")
            return
        
        registered_count = 0
        
        for i in range(num_members):
            print(f"\n--- Miembro #{i+1} ---")
            member_id = input("ID del miembro (ej: Director, leah, mar): ").strip()
            
            if not member_id:
                print("ID no especificado, saltando...")
                continue
            
            # Sugerir automáticamente el nombre del archivo
            suggested_file = f"public_key_{member_id}.pem"
            key_file = input(f"Archivo de llave pública [Enter para {suggested_file}]: ").strip()
            
            if not key_file:
                key_file = suggested_file
            elif not key_file.endswith('.pem'):
                key_file += '.pem'
            
            try:
                with open(key_file, 'r') as f:
                    public_key_pem = f.read()
                
                if self.key_gen.add_team_member_public_key(member_id, public_key_pem):
                    print(f"✅ Llave pública de '{member_id}' registrada exitosamente")
                    registered_count += 1
                else:
                    print(f"❌ Error registrando llave de '{member_id}'")
                    
            except FileNotFoundError:
                print(f"❌ Archivo no encontrado: {key_file}")
                print(f"   Asegúrate de que el archivo '{key_file}' existe")
            except Exception as e:
                print(f"❌ Error: {e}")
        
        # Guardar configuración
        if registered_count > 0:
            self.key_gen.save_public_keys_to_file("team_public_keys.json")
            print(f"\n✅ {registered_count} llaves registradas y guardadas en team_public_keys.json")
        else:
            print(f"\n⚠️  No se registraron llaves nuevas")
        
        input("\nPresione Enter para continuar...")
    
    def view_my_keys(self):
        self.clear_screen()
        self.print_header()
        print("🗝️ MIS LLAVES Y CONFIGURACIÓN DE EQUIPO")
        
        # Información del usuario actual
        print(f"\n👤 USUARIO ACTUAL: {self.current_user}")
        print("-" * 40)
        
        # Estado de las llaves en memoria
        if self.key_gen.private_key:
            print("✅ Llave privada CARGADA en memoria - LISTO PARA OPERACIONES")
        else:
            print("❌ Llave privada NO CARGADA en memoria")
        
        if self.key_gen.public_key:
            print("✅ Llave pública CARGADA en memoria")
        else:
            print("❌ Llave pública NO CARGADA en memoria")
        
        # Verificar archivos locales
        if self.key_gen.user_id:
            print(f"\n📁 ARCHIVOS LOCALES:")
            private_key_file = f"private_key_{self.key_gen.user_id}.pem"
            public_key_file = f"public_key_{self.key_gen.user_id}.pem"
            
            if os.path.exists(private_key_file):
                print(f"   ✅ {private_key_file}")
                if not self.key_gen.private_key:
                    print("   💡 Archivo existe pero NO CARGADO. Use 'Cargar mi llave privada'")
            else:
                print(f"   ❌ {private_key_file} (no existe)")
            
            if os.path.exists(public_key_file):
                print(f"   ✅ {public_key_file}")
            else:
                print(f"   ❌ {public_key_file} (no existe)")
        
        # Mostrar miembros del equipo registrados
        print(f"\n👥 EQUIPO REGISTRADO ({len(self.key_gen.team_public_keys)} miembros):")
        if self.key_gen.team_public_keys:
            for member_id in sorted(self.key_gen.team_public_keys.keys()):
                status = "✅" 
                print(f"   {status} {member_id}")
        else:
            print("   ❌ No hay miembros del equipo registrados")
            print("   💡 Use 'Registrar llaves públicas de equipo'")
        
        input("\nPresione Enter para continuar...")
    
    def encrypt_private_key(self):
        self.clear_screen()
        self.print_header()
        print("🔐 CIFRADO DE LLAVE PRIVADA")
        
        if not self.key_gen.private_key:
            print("❌ No hay llave privada cargada para cifrar")
            input("\nPresione Enter para continuar...")
            return
        
        password = input("Contraseña para cifrar la llave privada: ").strip()
        if not password:
            print("❌ La contraseña no puede estar vacía")
            input("\nPresione Enter para continuar...")
            return
        
        try:
            # Serializar llave privada
            private_pem = self.key_gen.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Guardar temporalmente
            temp_file = f"temp_private_{self.current_user}.pem"
            with open(temp_file, 'wb') as f:
                f.write(private_pem)
            
            # Cifrar llave
            result = self.key_encryptor.encrypt_key(temp_file, password)
            
            if result['success']:
                print(f"\n✅ Llave privada cifrada exitosamente:")
                print(f"   📄 Archivo cifrado: {result['encrypted_file']}")
                print(f"   🔑 Archivo de metadatos: {result['metadata_file']}")
                
                # Eliminar archivo temporal
                os.remove(temp_file)
            else:
                print(f"❌ Error cifrando llave: {result.get('error', 'Error desconocido')}")
                
        except Exception as e:
            print(f"❌ Error: {e}")
        
        input("\nPresione Enter para continuar...")
    
    def decrypt_private_key(self):
        self.clear_screen()
        self.print_header()
        print("🔓 DESCIFRADO DE LLAVE PRIVADA")
        
        encrypted_file = input("Archivo cifrado (.enc): ").strip()
        metadata_file = input("Archivo de metadatos (.meta): ").strip()
        password = input("Contraseña: ").strip()
        
        if not all([encrypted_file, metadata_file, password]):
            print("❌ Todos los campos son obligatorios")
            input("\nPresione Enter para continuar...")
            return
        
        try:
            result = self.key_decryptor.decrypt_key(encrypted_file, metadata_file, password)
            
            if result['success']:
                print(f"\n✅ Llave privada descifrada exitosamente:")
                print(f"   📄 Archivo descifrado: {result['decrypted_file']}")
                
                # Cargar la llave descifrada
                if self.key_gen.load_private_key(self.current_user):
                    print("✅ Llave privada cargada automáticamente")
            else:
                print(f"❌ Error descifrando llave: {result.get('error', 'Error desconocido')}")
                
        except Exception as e:
            print(f"❌ Error: {e}")
        
        input("\nPresione Enter para continuar...")
    
    def sign_document(self):
        self.clear_screen()
        self.print_header()
        print("📝 FIRMA DE DOCUMENTO")
        
        # Verificar que el usuario tenga llaves CARGADAS
        if not self.key_gen.private_key:
            print("❌ ERROR: No hay llave privada cargada")
            print("\nPosibles soluciones:")
            print("1. Use 'Generar mis llaves' si no tiene llaves")
            print("2. Use 'Cargar mi llave privada' si ya tiene llaves")
            
            input("\nPresione Enter para continuar...")
            return
        
        file_path = input("Ruta del documento a firmar: ").strip()
        if not file_path:
            print("Debe especificar una ruta de archivo")
            input("\nPresione Enter para continuar...")
            return
        
        if not os.path.exists(file_path):
            print(f"El documento no existe: {file_path}")
            input("\nPresione Enter para continuar...")
            return
        
        try:
            # Crear firma del documento
            signature_package = self.signer.sign_document(file_path)
            
            # Guardar firma
            signature_file = f"firma_{self.current_user}.json"
            saved_path = self.signer.save_signature_package(signature_package, signature_file)
            
            print(f"\n✅ Documento firmado exitosamente:")
            print(f"   📄 Documento: {file_path}")
            print(f"   📝 Firma guardada en: {saved_path}")
            print(f"   🔍 Hash del documento: {signature_package['document_hash']}")
            print(f"   📊 Tamaño del archivo: {os.path.getsize(file_path)} bytes")
            
        except Exception as e:
            print(f"❌ Error creando firma: {e}")
        
        input("\nPresione Enter para continuar...")
    
    def verify_individual_signature(self):
        self.clear_screen()
        self.print_header()
        print("🔍 VERIFICACIÓN DE FIRMA INDIVIDUAL")
        
        file_path = input("Ruta del documento: ").strip()
        if not file_path or not os.path.exists(file_path):
            print(f"❌ El documento no existe: {file_path}")
            input("\nPresione Enter para continuar...")
            return
        
        sig_file = input("Archivo de firma (.json): ").strip()
        if not sig_file.endswith('.json'):
            sig_file += '.json'
        
        try:
            with open(sig_file, 'r') as f:
                signature_package = json.load(f)
            print("✅ Firma cargada desde archivo")
        except Exception as e:
            print(f"❌ Error cargando firma: {e}")
            input("\nPresione Enter para continuar...")
            return
        
        try:
            valid = self.verifier.verify_signature(signature_package, file_path)
            if valid:
                user_id = signature_package.get('user_id', 'desconocido')
                print(f"\n✅ FIRMA VÁLIDA")
                print(f"   👤 Firmante: {user_id}")
                print(f"   📄 Documento: {os.path.basename(file_path)}")
                print("   ✅ El documento no ha sido modificado y la firma es auténtica.")
            else:
                print(f"\n❌ FIRMA INVÁLIDA")
                print("   ❌ El documento ha sido modificado o la firma es incorrecta.")
        except Exception as e:
            print(f"❌ Error verificando firma: {e}")
        
        input("\nPresione Enter para continuar...")
    
    def verify_multiple_signatures(self):
        self.clear_screen()
        self.print_header()
        print("🔍 VERIFICACIÓN DE MÚLTIPLES FIRMAS")
        
        # Verificar que hay llaves de equipo registradas
        if not self.key_gen.team_public_keys:
            print("❌ ERROR: No hay llaves públicas de equipo registradas")
            print("   Use 'Registrar llaves públicas de equipo' primero")
            input("\nPresione Enter para continuar...")
            return
        
        file_path = input("Ruta del documento: ").strip()
        if not file_path or not os.path.exists(file_path):
            print(f"❌ El documento no existe: {file_path}")
            input("\nPresione Enter para continuar...")
            return
        
        # Mostrar miembros registrados para referencia
        print(f"\n👥 Miembros registrados: {', '.join(sorted(self.key_gen.team_public_keys.keys()))}")
        
        # Usar la verificación interactiva del sistema
        try:
            result = self.verifier.verify_signatures_interactive(file_path)
            if result:
                print("\n🎉 VERIFICACIÓN EXITOSA - Todas las firmas son válidas")
            else:
                print("\n⚠️  VERIFICACIÓN PARCIAL - Algunas firmas son inválidas")
        except Exception as e:
            print(f"❌ Error durante la verificación: {e}")
        
        input("\nPresione Enter para continuar...")
    
    def collect_signatures(self):
        self.clear_screen()
        self.print_header()
        print("📦 RECOLECCIÓN DE FIRMAS")
        
        output_file = input("Nombre del archivo de salida (default: todas_firmas.json): ").strip()
        if not output_file:
            output_file = "todas_firmas.json"
        
        if not output_file.endswith('.json'):
            output_file += '.json'
        
        # Usar la colección interactiva del sistema
        try:
            result_file = self.signer.collect_signatures_interactive()
            print(f"\n✅ Firmas recolectadas en: {result_file}")
        except Exception as e:
            print(f"❌ Error recolectando firmas: {e}")
        
        input("\nPresione Enter para continuar...")
    
    def encrypt_document(self):
        self.clear_screen()
        self.print_header()
        print("🔒 CIFRADO DE DOCUMENTO")
        
        file_path = input("Ruta del documento a cifrar: ").strip()
        if not file_path or not os.path.exists(file_path):
            print(f"❌ El documento no existe: {file_path}")
            input("\nPresione Enter para continuar...")
            return
        
        password = input("Contraseña para cifrado: ").strip()
        if not password:
            print("❌ La contraseña no puede estar vacía")
            input("\nPresione Enter para continuar...")
            return
        
        try:
            result = self.encryptor.encrypt_document(file_path, password)
            
            if result['success']:
                print(f"\n✅ Documento cifrado exitosamente:")
                print(f"   📄 Archivo cifrado: {result['encrypted_path']}")
                print(f"   📋 Metadatos: {result['metadata_path']}")
                print(f"   📊 Tamaño original: {os.path.getsize(file_path)} bytes")
                print(f"   📊 Tamaño cifrado: {os.path.getsize(result['encrypted_path'])} bytes")
            else:
                print(f"❌ Error cifrando documento: {result.get('error', 'Error desconocido')}")
                
        except Exception as e:
            print(f"❌ Error: {e}")
        
        input("\nPresione Enter para continuar...")
    
    def decrypt_document(self):
        self.clear_screen()
        self.print_header()
        print("🔓 DESCIFRADO DE DOCUMENTO")
        
        encrypted_file = input("Archivo cifrado: ").strip()
        metadata_file = input("Archivo de metadatos: ").strip()
        password = input("Contraseña: ").strip()
        
        if not all([encrypted_file, metadata_file, password]):
            print("❌ Todos los campos son obligatorios")
            input("\nPresione Enter para continuar...")
            return
        
        if not os.path.exists(encrypted_file) or not os.path.exists(metadata_file):
            print("❌ Uno o más archivos no existen")
            input("\nPresione Enter para continuar...")
            return
        
        try:
            result = self.decryptor.decrypt_document(encrypted_file, metadata_file, password)
            
            if result['success']:
                print(f"\n✅ Documento descifrado exitosamente:")
                print(f"   📄 Archivo descifrado: {result['decrypted_path']}")
                print(f"   📄 Nombre original: {result['original_filename']}")
            else:
                print(f"❌ Error descifrando documento: {result.get('error', 'Error desconocido')}")
                
        except Exception as e:
            print(f"❌ Error: {e}")
        
        input("\nPresione Enter para continuar...")
    
    def encrypt_document_team(self):
        self.clear_screen()
        self.print_header()
        print("🔒 CIFRADO DE DOCUMENTO PARA EQUIPO")
        
        file_path = input("Ruta del documento a cifrar: ").strip()
        if not file_path or not os.path.exists(file_path):
            print(f"❌ El documento no existe: {file_path}")
            input("\nPresione Enter para continuar...")
            return
        
        team_password = input("Contraseña del equipo: ").strip()
        if not team_password:
            print("❌ La contraseña del equipo no puede estar vacía")
            input("\nPresione Enter para continuar...")
            return
        
        try:
            result = self.encryptor.encrypt_document(file_path, team_password)
            
            if result['success']:
                print(f"\n✅ Documento cifrado para equipo exitosamente:")
                print(f"   📄 Archivo cifrado: {result['encrypted_path']}")
                print(f"   📋 Metadatos: {result['metadata_path']}")
            else:
                print(f"❌ Error cifrando documento: {result.get('error', 'Error desconocido')}")
                
        except Exception as e:
            print(f"❌ Error: {e}")
        
        input("\nPresione Enter para continuar...")
    
    def decrypt_document_team(self):
        self.clear_screen()
        self.print_header()
        print("🔓 DESCIFRADO DE DOCUMENTO DE EQUIPO")
        
        encrypted_file = input("Archivo cifrado: ").strip()
        metadata_file = input("Archivo de metadatos: ").strip()
        team_password = input("Contraseña del equipo: ").strip()
        
        if not all([encrypted_file, metadata_file, team_password]):
            print("❌ Todos los campos son obligatorios")
            input("\nPresione Enter para continuar...")
            return
        
        if not os.path.exists(encrypted_file) or not os.path.exists(metadata_file):
            print("❌ Uno o más archivos no existen")
            input("\nPresione Enter para continuar...")
            return
        
        try:
            result = self.decryptor.decrypt_document(encrypted_file, metadata_file, team_password)
            
            if result['success']:
                print(f"\n✅ Documento descifrado exitosamente:")
                print(f"   📄 Archivo descifrado: {result['decrypted_path']}")
                print(f"   📄 Nombre original: {result['original_filename']}")
            else:
                print(f"❌ Error descifrando documento: {result.get('error', 'Error desconocido')}")
                
        except Exception as e:
            print(f"❌ Error: {e}")
        
        input("\nPresione Enter para continuar...")
    
    def change_user(self):
        self.clear_screen()
        self.print_header()
        new_user = input("Nuevo nombre de usuario: ").strip()
        if new_user:
            self.current_user = new_user
            self.key_gen.user_id = new_user
            print(f"Usuario cambiado a: {new_user}")
            
            # Intentar cargar llave privada del nuevo usuario automáticamente
            if self.key_gen.load_private_key(new_user):
                print(f"✅ Llave privada de {new_user} cargada automáticamente")
            else:
                print(f"⚠️  No se encontró llave privada existente para {new_user}")
                print(f"   Use 'Generar mis llaves' o 'Cargar mi llave privada'")
        input("Presione Enter para continuar...")

if __name__ == "__main__":
    app = ConsoleInterface()
    app.main_menu()