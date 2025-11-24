import os
import base64
import json
from mainhearth import signverify

class ConsoleInterface:
    def __init__(self):
        self.system = signverify()
        self.current_user = "Director"
        # Cargar configuración automáticamente al iniciar
        self.load_configuration()
        # Intentar cargar llave privada del usuario actual automáticamente
        self.load_current_user_private_key()
        
    def load_configuration(self):
        """Cargar configuración automáticamente al iniciar"""
        if os.path.exists("team_public_keys.json"):
            if self.system.load_public_keys_from_file("team_public_keys.json"):
                print("✓ Configuración de equipo cargada automáticamente")
    
    def load_current_user_private_key(self):
        """Intentar cargar la llave privada del usuario actual automáticamente"""
        if self.current_user:
            if self.system.load_privk(self.current_user):
                print(f"✓ Llave privada de {self.current_user} cargada automáticamente")
            else:
                print(f"⚠️  No se pudo cargar llave privada de {self.current_user}")
                print("   Use 'Generar mis llaves' o 'Cargar mi llave privada'")
    
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_header(self):
        print("=" * 50)
        print("    Firma Pearson & Specter ")
        print("=" * 50)
        print(f"Usuario: {self.current_user}")
        # Mostrar estado de las llaves en el header
        if self.system.private_key:
            print("Estado: ✅ LLAVES CARGADAS - Listo para firmar")
        else:
            print("Estado: ❌ SIN LLAVES - No puede firmar")
        print()
    
    def main_menu(self):
        while True:
            self.clear_screen()
            self.print_header()
            print("1. Generar mis llaves")
            print("2. Registrar llaves públicas de equipo")
            print("3. Ver mis llaves y equipo")
            print("4. Configuración")
            print("5. Crear firma digital de documento")
            print("6. Verificar firma individual")
            print("7. Verificar múltiples firmas")
            print("8. Recolectar firmas en archivo")
            print("0. Salir")
            print()
            
            choice = input("Seleccione una opción: ").strip()
            
            if choice == "1":
                self.generate_keys()
            elif choice == "2":
                self.register_team_keys()
            elif choice == "3":
                self.view_my_keys()
            elif choice == "4":
                self.config_menu()
            elif choice == "5":
                self.sign_document()
            elif choice == "6":
                self.verify_individual_signature()
            elif choice == "7":
                self.verify_multiple_signatures()
            elif choice == "8":
                self.collect_signatures()
            elif choice == "0":
                print("Saliendo...")
                break
            else:
                input("Opción inválida. Presione Enter para continuar...")
    
    def generate_keys(self):
        self.clear_screen()
        self.print_header()
        
        # Preguntar si ya existen llaves
        private_key_file = f"private_key_{self.current_user}.pem"
        if os.path.exists(private_key_file):
            overwrite = input(f"⚠️  Ya existe una llave para {self.current_user}. ¿Regenerar? (s/n): ").strip().lower()
            if overwrite != 's':
                print("Operación cancelada.")
                input("\nPresione Enter para continuar...")
                return
        
        self.system.user_id = self.current_user
        public_key_pem = self.system.gen_kpair()
        
        print("🗝️ Llaves generadas")
        print(f" Llave privada guardada en: private_key_{self.current_user}.pem")
        print(f" Llave pública guardada en: public_key_{self.current_user}.pem")
        
        # Registrar automáticamente la llave pública del usuario actual
        if self.system.add_team_member_public_key(self.current_user, public_key_pem):
            print(f"✓ Llave pública de {self.current_user} registrada en equipo")
            self.system.save_public_keys_to_file("team_public_keys.json")
        
        input("\nPresione Enter para continuar...")
    
    def sign_document(self):
        self.clear_screen()
        self.print_header()
        print("FIRMAR DOCUMENTO")
        
        # Verificar que el usuario tenga llaves CARGADAS
        if not self.system.private_key:
            print("❌ ERROR: No hay llave privada cargada")
            print("\nPosibles soluciones:")
            print("1. Use 'Generar mis llaves' (Opción 1) si no tiene llaves")
            print("2. Use 'Configuración → Cargar mi llave privada' (Opción 4→3) si ya tiene llaves")
            print("3. Verifique que el archivo private_key_{self.current_user}.pem existe")
            
            # Verificar si el archivo existe pero no está cargado
            private_key_file = f"private_key_{self.current_user}.pem"
            if os.path.exists(private_key_file):
                print(f"\n💡 El archivo {private_key_file} EXISTE pero no está cargado.")
                load_now = input("¿Cargar ahora? (s/n): ").strip().lower()
                if load_now == 's':
                    if self.system.load_privk(self.current_user):
                        print("✅ Llave privada cargada exitosamente")
                        # Intentar firmar de nuevo
                        input("Presione Enter para intentar firmar nuevamente...")
                        self.sign_document()
                        return
            else:
                print(f"\n💡 El archivo {private_key_file} NO EXISTE.")
                print("   Use 'Generar mis llaves' para crear nuevas llaves.")
            
            input("\nPresione Enter para continuar...")
            return
        
        # Si llegamos aquí, las llaves están cargadas
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
            signature_package = self.system.sign_document(file_path)
            
            # Guardar firma
            signature_file = f"firma_{self.current_user}.json"
            saved_path = self.system.save_signature_package(signature_package, signature_file)
            
            print(f"✓ Documento firmado: {file_path}")
            print(f"✓ Firma guardada en: {saved_path}")
            print(f"✓ Hash del documento: {signature_package['document_hash']}")
            print(f"✓ Tamaño del archivo: {os.path.getsize(file_path)} bytes")
            
        except Exception as e:
            print(f"✗ Error creando firma: {e}")
        
        input("\nPresione Enter para continuar...")

    def view_my_keys(self):
        self.clear_screen()
        self.print_header()
        print("🗝️ MIS LLAVES Y CONFIGURACIÓN DE EQUIPO 🗝️")
        
        # Información del usuario actual
        print(f"\n👤 USUARIO ACTUAL: {self.current_user}")
        print("-" * 40)
        
        # Estado de las llaves en memoria
        if self.system.private_key:
            print("✅ Llave privada CARGADA en memoria - LISTO PARA FIRMAR")
        else:
            print("❌ Llave privada NO CARGADA en memoria - NO PUEDE FIRMAR")
        
        if self.system.public_key:
            print("✅ Llave pública CARGADA en memoria")
        else:
            print("❌ Llave pública NO CARGADA en memoria")
        
        # Verificar archivos locales
        if self.system.user_id:
            print(f"\n📁 ARCHIVOS LOCALES:")
            private_key_file = f"private_key_{self.system.user_id}.pem"
            public_key_file = f"public_key_{self.system.user_id}.pem"
            
            if os.path.exists(private_key_file):
                print(f"   ✅ {private_key_file}")
                if not self.system.private_key:
                    print("   💡 Archivo existe pero NO CARGADO. Use 'Cargar mi llave privada'")
            else:
                print(f"   ❌ {private_key_file} (no existe)")
            
            if os.path.exists(public_key_file):
                print(f"   ✅ {public_key_file}")
            else:
                print(f"   ❌ {public_key_file} (no existe)")
        
        # Mostrar miembros del equipo registrados
        print(f"\n👥 EQUIPO REGISTRADO ({len(self.system.team_public_keys)} miembros):")
        if self.system.team_public_keys:
            for member_id in sorted(self.system.team_public_keys.keys()):
                status = "✅" 
                print(f"   {status} {member_id}")
        else:
            print("   ❌ No hay miembros del equipo registrados")
            print("   💡 Use la Opción 2 para registrar llaves públicas")
        
        # Acciones recomendadas
        print(f"\n🚀 ACCIONES RECOMENDADAS:")
        if not self.system.private_key:
            if os.path.exists(f"private_key_{self.current_user}.pem"):
                print("   1. Use 'Configuración → Cargar mi llave privada'")
            else:
                print("   1. Use 'Generar mis llaves'")
        else:
            print("   1. ✅ Listo para firmar documentos")
        
        input("\nPresione Enter para continuar...")

    def config_menu(self):
        while True:
            self.clear_screen()
            self.print_header()
            print("CONFIGURACIÓN")
            print("1. Guardar configuración de equipo")
            print("2. Cargar configuración de equipo")
            print("3. Cargar mi llave privada")
            print("4. Cambiar usuario")
            print("5. Volver al menú principal")
            
            choice = input("Seleccione una opción: ").strip()
            
            if choice == "1":
                filename = input("Nombre del archivo (team_public_keys.json): ").strip() or "team_public_keys.json"
                self.system.save_public_keys_to_file(filename)
                print("✓ Configuración guardada")
                input("Presione Enter para continuar...")
            elif choice == "2":
                filename = input("Nombre del archivo (team_public_keys.json): ").strip() or "team_public_keys.json"
                if self.system.load_public_keys_from_file(filename):
                    print("✓ Configuración cargada")
                    print(f"Miembros del equipo: {len(self.system.team_public_keys)}")
                else:
                    print("✗ Archivo no encontrado")
                input("Presione Enter para continuar...")
            elif choice == "3":
                user_id = input(f"ID de usuario [Enter para {self.current_user}]: ").strip()
                if not user_id:
                    user_id = self.current_user
                
                if self.system.load_privk(user_id):
                    self.current_user = user_id
                    self.system.user_id = user_id
                    print(f"✅ Llave privada de {user_id} cargada exitosamente")
                    print("✅ Ahora puede firmar documentos")
                else:
                    print(f"❌ No se encontró llave privada para {user_id}")
                    print(f"   Verifique que el archivo private_key_{user_id}.pem existe")
                input("Presione Enter para continuar...")
            elif choice == "4":
                self.change_user()
            elif choice == "5":
                break
            else:
                input("Opción inválida. Presione Enter para continuar...")

    def change_user(self):
        self.clear_screen()
        self.print_header()
        new_user = input("Nuevo nombre de usuario: ").strip()
        if new_user:
            self.current_user = new_user
            self.system.user_id = new_user
            print(f"Usuario cambiado a: {new_user}")
            
            # Intentar cargar llave privada del nuevo usuario automáticamente
            if self.system.load_privk(new_user):
                print(f"✅ Llave privada de {new_user} cargada automáticamente")
            else:
                print(f"⚠️  No se encontró llave privada existente para {new_user}")
                print(f"   Use 'Generar mis llaves' o 'Cargar mi llave privada'")
        input("Presione Enter para continuar...")

if __name__ == "__main__":
    app = ConsoleInterface()
    app.main_menu()