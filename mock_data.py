import json
import random

def generate_employee_data():
    """Genera datos mock de empleados organizados en células"""
    
    employees = {
        "celula_A": [
            {
                "id": "emp_001",
                "nombre": "Ana",
                "apellido1": "García",
                "apellido2": "López",
                "cedula": f"{random.randint(1000, 9999)}",
                "password": "password",
                "public_key": None,
                "firma": None
            },
            {
                "id": "emp_002", 
                "nombre": "Carlos",
                "apellido1": "Rodríguez",
                "apellido2": "Martínez",
                "cedula": f"{random.randint(1000, 9999)}",
                "password": "password",
                "public_key": None,
                "firma": None
            },
            {
                "id": "emp_003",
                "nombre": "María",
                "apellido1": "Fernández",
                "apellido2": "Gómez", 
                "cedula": f"{random.randint(1000, 9999)}",
                "password": "password",
                "public_key": None,
                "firma": None
            }
        ],
        "celula_B": [
            {
                "id": "emp_004",
                "nombre": "Juan",
                "apellido1": "Pérez",
                "apellido2": "Hernández",
                "cedula": f"{random.randint(1000, 9999)}",
                "password": "password",
                "public_key": None,
                "firma": None
            },
            {
                "id": "emp_005",
                "nombre": "Laura",
                "apellido1": "Díaz",
                "apellido2": "Castillo",
                "cedula": f"{random.randint(1000, 9999)}",
                "password": "password", 
                "public_key": None,
                "firma": None
            },
            {
                "id": "emp_006",
                "nombre": "Pedro",
                "apellido1": "Sánchez",
                "apellido2": "Ramírez",
                "cedula": f"{random.randint(1000, 9999)}",
                "password": "password",
                "public_key": None,
                "firma": None
            }
        ]
    }
    
    return employees

def save_employee_data(employees, filename="employees.json"):
    """Guarda los datos de empleados en un archivo JSON"""
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(employees, f, indent=2, ensure_ascii=False)

def load_employee_data(filename="employees.json"):
    """Carga los datos de empleados desde un archivo JSON"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        # Si no existe, generar datos nuevos
        employees = generate_employee_data()
        save_employee_data(employees, filename)
        return employees

def update_employee_public_key(employee_id, public_key_pem, filename="employees.json"):
    """Actualiza la llave pública de un empleado"""
    employees = load_employee_data(filename)
    
    for celula in employees.values():
        for employee in celula:
            if employee["id"] == employee_id:
                employee["public_key"] = public_key_pem
                save_employee_data(employees, filename)
                return True
    return False

def update_employee_signature(employee_id, signature, filename="employees.json"):
    """Actualiza la firma de un empleado"""
    employees = load_employee_data(filename)
    
    for celula in employees.values():
        for employee in celula:
            if employee["id"] == employee_id:
                employee["firma"] = signature
                save_employee_data(employees, filename)
                return True
    return False

# Generar datos iniciales si se ejecuta directamente
if __name__ == "__main__":
    employees = generate_employee_data()
    save_employee_data(employees)
    print("Datos de empleados generados y guardados en employees.json")