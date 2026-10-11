
# Menu interactivo adicional de Python Keytool

from getpass import getpass

from keystore import (
    create_keystore,
    save_keystore,
    list_aliases,
    get_key
)

from keytool import genkeypair, certreq
from verify_csr import verify_csr, show_csr_info


# ==========================================
# ================ MENU ====================
# ==========================================

def show_menu():
    print()
    print("===================================")
    print("          PYTHON KEYTOOL")
    print("===================================")
    print("1. Preparar KeyStore vacio")
    print("2. Generar par de claves")
    print("3. Listar aliases")
    print("4. Mostrar informacion de un alias")
    print("5. Generar CSR")
    print("6. Verificar CSR")
    print("7. Salir")
    print("===================================")


# ==========================================
# =========== CREATE KEYSTORE ==============
# ==========================================

def create_keystore_option():
    password = getpass("Contrasena del KeyStore: ")

    if not password:
        print("Error: la contrasena no puede estar vacia.")
        return

    try:
        create_keystore()
        save_keystore({}, password)
        print("KeyStore vacio creado correctamente.")
    except (ValueError, OSError) as error:
        print("Error:", error)


# ==========================================
# ============ LIST ALIASES ================
# ==========================================

def show_aliases():
    password = getpass("Contrasena del KeyStore: ")

    try:
        aliases = list_aliases(password)

        if not aliases:
            print("El KeyStore esta vacio.")
        else:
            print("Aliases del KeyStore:")
            for alias in aliases:
                print("-", alias)

    except (ValueError, OSError) as error:
        print("Error:", error)


# ==========================================
# ========== SHOW INFORMATION ==============
# ==========================================

def show_information():
    password = getpass("Contrasena del KeyStore: ")
    alias = input("Alias: ").strip()

    try:
        key_data = get_key(alias, password)

        print("Alias:", alias)
        print("Subject:", key_data["subject"])
        print("Clave privada almacenada: SI")

    except (ValueError, OSError) as error:
        print("Error:", error)


# ==========================================
# ============= VERIFY CSR =================
# ==========================================

def verify_csr_option():
    filepath = input("Ruta de la CSR: ").strip()

    if not filepath:
        print("Error: debes indicar la ruta de la CSR.")
        return

    try:
        csr = verify_csr(filepath)
        print("CSR valida correctamente.")
        show_csr_info(csr)

    except (ValueError, OSError) as error:
        print("Error:", error)


# ==========================================
# ================= MAIN ===================
# ==========================================

def main():
    while True:
        show_menu()
        option = input("Selecciona una opcion: ").strip()

        if option == "1":
            create_keystore_option()
        elif option == "2":
            genkeypair()
        elif option == "3":
            show_aliases()
        elif option == "4":
            show_information()
        elif option == "5":
            certreq()
        elif option == "6":
            verify_csr_option()
        elif option == "7":
            print("Saliendo de Python Keytool...")
            break
        else:
            print("Opcion no valida.")


if __name__ == "__main__":
    main()