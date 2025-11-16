import os
from key_exchange_core import KeyExchangeSystem
import base64

class ConsoleInterface:
    def __init__(self):
        self.system = KeyExchangeSystem()
        self.current_user = "Director"
        
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_header(self):
        print("=" * 50)
        print("    SISTEMA DE INTERCAMBIO SECRETO DE LLAVES")
        print("=" * 50)
        print(f"Usuario: {self.current_user}")
        print()
    
    def main_menu(self):
        while True:
            self.clear_screen()
            self.print_header()
            print("MENÚ PRINCIPAL")
            print("1. Generar mis llaves")
            print("2. Agregar llave pública de miembro")
            print("3. Generar y distribuir llave simétrica")
            print("4. Ver mis llaves")
            print("5. Ver miembros del equipo")
            print("6. Guardar/Cargar configuración")
            print("7. Cambiar usuario")
            print("8. Salir")
            print()
            
            choice = input("Seleccione una opción: ").strip()
            
            if choice == "1":
                self.generate_keys()
            elif choice == "2":
                self.add_member_key()
            elif choice == "3":
                self.distribute_symmetric_key()
            elif choice == "4":
                self.view_my_keys()
            elif choice == "5":
                self.view_team_members()
            elif choice == "6":
                self.config_menu()
            elif choice == "7":
                self.change_user()
            elif choice == "8":
                print("¡Hasta luego!")
                break
            else:
                input("Opción inválida. Presione Enter para continuar...")
    
    def generate_keys(self):
        self.clear_screen()
        self.print_header()
        print("GENERANDO LLAVES RSA...")
        
        self.system.generate_key_pair()
        print("✓ Llaves generadas exitosamente")
        print(f"Llave pública: {self.system.get_public_key_pem()[:50]}...")
        input("\nPresione Enter para continuar...")
    
    def add_member_key(self):
        self.clear_screen()
        self.print_header()
        print("AGREGAR LLAVE PÚBLICA DE MIEMBRO")
        
        member_id = input("ID del miembro: ").strip()
        public_key_pem = input("Pegue la llave pública PEM: ").strip()
        
        if self.system.add_team_member_public_key(member_id, public_key_pem):
            print(f"✓ Llave pública de {member_id} agregada exitosamente")
        else:
            print("✗ Error al agregar la llave pública")
        
        input("\nPresione Enter para continuar...")
    
    def distribute_symmetric_key(self):
        self.clear_screen()
        self.print_header()
        print("GENERAR Y DISTRIBUIR LLAVE SIMÉTRICA")
        
        if not self.system.team_public_keys:
            print("No hay miembros en el equipo. Agregue primero algunas llaves públicas.")
            input("\nPresione Enter para continuar...")
            return
        
        key_name = input("Nombre para esta llave simétrica: ").strip()
        symmetric_key = self.system.generate_symmetric_key()
        
        print(f"\nLlave simétrica generada: {base64.b64encode(symmetric_key).decode('utf-8')[:30]}...")
        print("\nLlaves encriptadas para cada miembro:")
        
        for member_id in self.system.team_public_keys.keys():
            try:
                encrypted_key = self.system.encrypt_symmetric_key(member_id, symmetric_key)
                print(f"\n{member_id}:")
                print(f"  {encrypted_key}")
            except Exception as e:
                print(f"✗ Error encriptando para {member_id}: {e}")
        
        self.system.symmetric_keys[key_name] = base64.b64encode(symmetric_key).decode('utf-8')
        input("\nPresione Enter para continuar...")
    
    def view_my_keys(self):
        self.clear_screen()
        self.print_header()
        print("MIS LLAVES")
        
        if self.system.public_key:
            print("\nLlave Pública:")
            print(self.system.get_public_key_pem())
        else:
            print("No hay llaves generadas.")
        
        if self.system.symmetric_keys:
            print("\nLlaves Simétricas:")
            for name, key in self.system.symmetric_keys.items():
                print(f"{name}: {key[:30]}...")
        
        input("\nPresione Enter para continuar...")
    
    def view_team_members(self):
        self.clear_screen()
        self.print_header()
        print("MIEMBROS DEL EQUIPO")
        
        if not self.system.team_public_keys:
            print("No hay miembros en el equipo.")
        else:
            for member_id in self.system.team_public_keys.keys():
                print(f"• {member_id}")
        
        input("\nPresione Enter para continuar...")
    
    def config_menu(self):
        while True:
            self.clear_screen()
            self.print_header()
            print("CONFIGURACIÓN")
            print("1. Guardar configuración")
            print("2. Cargar configuración")
            print("3. Volver al menú principal")
            
            choice = input("Seleccione una opción: ").strip()
            
            if choice == "1":
                filename = input("Nombre del archivo (keys.json): ").strip() or "keys.json"
                self.system.save_keys_to_file(filename)
                print("✓ Configuración guardada")
                input("Presione Enter para continuar...")
            elif choice == "2":
                filename = input("Nombre del archivo (keys.json): ").strip() or "keys.json"
                if self.system.load_keys_from_file(filename):
                    print("✓ Configuración cargada")
                else:
                    print("✗ Archivo no encontrado")
                input("Presione Enter para continuar...")
            elif choice == "3":
                break
            else:
                input("Opción inválida. Presione Enter para continuar...")
    
    def change_user(self):
        self.clear_screen()
        self.print_header()
        new_user = input("Nuevo nombre de usuario: ").strip()
        if new_user:
            self.current_user = new_user
            print(f"Usuario cambiado a: {new_user}")
        input("Presione Enter para continuar...")

if __name__ == "__main__":
    app = ConsoleInterface()
    app.main_menu()