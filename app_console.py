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
        
    def load_configuration(self):
        """Cargar configuración automáticamente al iniciar"""
        if os.path.exists("team_public_keys.json"):
            if self.system.load_public_keys_from_file("team_public_keys.json"):
                print("✓ Configuración de equipo cargada automáticamente")
    
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_header(self):
        print("=" * 50)
        print("    Firma Pearson & Specter ")
        print("=" * 50)
        print(f"Usuario: {self.current_user}")
        print()
    
    def main_menu(self):
        while True:
            self.clear_screen()
            self.print_header()
            print("1. Generar mis llaves")
            print("2. Registrar llaves públicas de equipo")
            print("3. Ver mis llaves y equipo")
            print("4. Configuración")
            print("5. Firmar documento")
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
        
        self.system.user_id = self.current_user
        public_key_pem = self.system.gen_kpair()
        
        print("🗝️ Llaves generadas")
        print(f" Llave privada guardada en: private_key_{self.current_user}.pem")
        print(f" Llave pública guardada en: public_key_{self.current_user}.pem")
        
        if self.system.add_team_member_public_key(self.current_user, public_key_pem):
            print(f"✓ Llave pública de {self.current_user} registrada en equipo")
            self.system.save_public_keys_to_file("team_public_keys.json")
        
        input("\nPresione Enter para continuar...")
    
    def register_team_keys(self):
        self.clear_screen()
        self.print_header()
        print("Registrar las llaves publicas de los empleados")
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
            member_id = input("ID del miembro (username): ").strip()
            
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
                
                if self.system.add_team_member_public_key(member_id, public_key_pem):
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
            self.system.save_public_keys_to_file("team_public_keys.json")
            print(f"\n✅ {registered_count} llaves registradas y guardadas en team_public_keys.json")
        else:
            print(f"\n⚠️  No se registraron llaves nuevas")
        
        input("\nPresione Enter para continuar...")
    
    def view_my_keys(self):
        self.clear_screen()
        self.print_header()
        print("🗝️ Llaves y Configuración 🗝️")
        
        print(f"\n👤 USUARIO: {self.current_user}")
        print("-" * 40)
        
        if self.system.public_key:
            print("✅ Llaves generadas")
        else:
            print("❌ No hay llaves generadas")
        
        # Verificar archivos locales
        if self.system.user_id:
            print(f"\n📁 Guardado local:")
            private_key_file = f"private_key_{self.system.user_id}.pem"
            public_key_file = f"public_key_{self.system.user_id}.pem"
            
            if os.path.exists(private_key_file):
                print(f"   ✅ private_key_{self.system.user_id}.pem")
            else:
                print(f"   ❌ private_key_{self.system.user_id}.pem (no existe)")
            
            if os.path.exists(public_key_file):
                print(f"   ✅ public_key_{self.system.user_id}.pem")
            else:
                print(f"   ❌ public_key_{self.system.user_id}.pem (no existe)")
        
        # llaves publicas registradas
        print(f"\n👥 Equipo registrado ({len(self.system.team_public_keys)} miembros):")
        if self.system.team_public_keys:
            for member_id in sorted(self.system.team_public_keys.keys()):
                status = "✅" if member_id in self.system.team_public_keys else "❌"
                print(f"   {status} {member_id}")
        else:
            print("   ❌ No hay miembros del equipo registrados")
            print("   💡 Use la Opción 2 para registrar llaves públicas")
        
        # config
        config_file = "team_public_keys.json"
        if os.path.exists(config_file):
            print(f"\n💾 CONFIGURACIÓN: team_public_keys.json (existe)")
        else:
            print(f"\n💾 CONFIGURACIÓN: team_public_keys.json (no existe)")
        
        input("\nPresione Enter para continuar...")
    
    

    # FIRMAS 
    def sign_document(self):
        self.clear_screen()
        self.print_header()
        print("FIRMAR DOCUMENTO")
        
        if not self.system.private_key:
            print("Debe generar sus llaves primero (Opción 1)")
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


    def verify_individual_signature(self):
        self.clear_screen()
        self.print_header()
        print("VERIFICAR FIRMA INDIVIDUAL")
        
        file_path = input("Documento: ").strip()
        if not file_path or not os.path.exists(file_path):
            print(f"El documento no existe: {file_path}")
            input("\nPresione Enter para continuar...")
            return
        
        sig_file = input("Archivo de firma (.json): ").strip()
        if not sig_file.endswith('.json'):
            sig_file += '.json'
        
        try:
            with open(sig_file, 'r') as f:
                signature_package = json.load(f)
            print("✓ Firma cargada desde archivo")
        except Exception as e:
            print(f"✗ Error cargando firma: {e}")
            input("\nPresione Enter para continuar...")
            return
        
        try:
            valid = self.system.verify_signature(signature_package, file_path)
            if valid:
                user_id = signature_package.get('user_id', 'desconocido')
                print(f"\n✅ FIRMA VÁLIDA")
                print(f"Firmante: {user_id}")
                print(f"Documento: {os.path.basename(file_path)}")
                print("El documento no ha sido modificado y la firma es auténtica.")
            else:
                print(f"\n❌ FIRMA INVÁLIDA")
                print("El documento ha sido modificado o la firma es incorrecta.")
        except Exception as e:
            print(f"✗ Error verificando firma: {e}")
        
        input("\nPresione Enter para continuar...")
    
    def verify_multiple_signatures(self):
        self.clear_screen()
        self.print_header()
        print("VERIFICAR MÚLTIPLES FIRMAS")
        
        if not self.system.team_public_keys:
            print("❌ ERROR: No hay llaves públicas de equipo registradas")
            print("   Use la Opción 2 para registrar las llaves públicas")
            print("   o la Opción 3 para verificar la configuración")
            input("\nPresione Enter para continuar...")
            return
        
        file_path = input("Ruta del documento: ").strip()
        if not file_path or not os.path.exists(file_path):
            print(f"❌ El documento no existe: {file_path}")
            input("\nPresione Enter para continuar...")
            return
        
        print(f"\n👥 Miembros registrados: {', '.join(sorted(self.system.team_public_keys.keys()))}")
        
        try:
            result = self.system.verify_signatures_interactive(file_path)
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
        print("RECOLECTAR FIRMAS EN ARCHIVO")
        
        output_file = input("Nombre del archivo de salida (default: todas_firmas.json): ").strip()
        if not output_file:
            output_file = "todas_firmas.json"
        
        if not output_file.endswith('.json'):
            output_file += '.json'
        
        # Usar la colección interactiva del sistema
        try:
            result_file = self.system.collect_signatures_interactive()
            print(f"\n✓ Firmas recolectadas en: {result_file}")
        except Exception as e:
            print(f"✗ Error recolectando firmas: {e}")
        
        input("\nPresione Enter para continuar...")
    


    #CAMBIAR DE USUARIO Y MENU DE CONFIG 

    def config_menu(self):
        while True:
            self.clear_screen()
            self.print_header()
            print("Settings ")
            print("1. Guardar configuración de equipo")
            print("2. Cargar configuración de equipo")
            print("3. Cambiar usuario")
            print("0. <-")
            
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
                self.change_user()
            elif choice == "0":
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
            
            # Intentar cargar llave privada del nuevo usuario
            if self.system.load_privk(new_user):
                print(f"✓ Llave privada de {new_user} cargada automáticamente")
            else:
                print(f"ℹ No se encontró llave privada existente para {new_user}")
        input("Presione Enter para continuar...")


if __name__ == "__main__":
    app = ConsoleInterface()
    app.main_menu()