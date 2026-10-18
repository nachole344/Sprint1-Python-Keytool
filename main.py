# menu interactivo adicional de python keytool
# permite utilizar las funciones del programa desde un menu de opciones

# importar getpass para pedir la contrasena sin mostrarla por pantalla
from getpass import getpass

# importar las funciones para crear y gestionar el keystore
from keystore import (
    create_keystore,
    keystore_exists,
    save_keystore,
    list_aliases,
    get_key,
    entry_type,
    input_path
)

# importar las funciones para generar claves y solicitudes csr
from commands import genkeypair, certreq

# importar las funciones para verificar una csr y mostrar su informacion
from verify_csr import verify_csr, show_csr_info


# ==========================================
# ================ MENU ====================
# ==========================================

def show_menu():
    # dejar una linea en blanco para separar el menu del texto anterior
    print()

    # mostrar el titulo del programa
    print("===================================")
    print("          PYTHON KEYTOOL")
    print("===================================")

    # mostrar las opciones disponibles para el usuario
    print("1. Preparar KeyStore vacio")
    print("2. Generar par de claves")
    print("3. Listar aliases")
    print("4. Mostrar informacion de un alias")
    print("5. Generar CSR")
    print("6. Verificar CSR")
    print("7. Salir")

    # mostrar la linea final del menu
    print("===================================")


# ==========================================
# =========== CREATE KEYSTORE ==============
# ==========================================

def create_keystore_option():
    # pedir la contrasena que se utilizara para proteger el keystore
    password = getpass("Contrasena del KeyStore: ")

    # comprobar que la contrasena no este vacia
    if not password:
        print("Error: la contrasena no puede estar vacia.")
        return

    # no sobrescribir un keystore existente: se perderian todas sus claves
    if keystore_exists():
        print("Error: el KeyStore ya existe. No se puede crear de nuevo.")
        return

    try:
        # crear la carpeta necesaria para guardar el keystore
        create_keystore()

        # guardar un diccionario vacio para crear el almacen sin claves
        # el contenido se guarda cifrado utilizando la contrasena
        save_keystore({}, password)

        # mostrar un mensaje si el almacen se ha creado correctamente
        print("KeyStore vacio creado correctamente.")

    # controlar errores relacionados con los datos o los archivos
    except (ValueError, OSError) as error:
        print("Error:", error)


# ==========================================
# ============ LIST ALIASES ================
# ==========================================

def show_aliases():
    # pedir la contrasena para acceder al keystore
    password = getpass("Contrasena del KeyStore: ")

    try:
        # recuperar la lista de aliases guardados en el almacen
        aliases = list_aliases(password)

        # comprobar si el almacen no contiene ninguna clave
        if not aliases:
            print("El KeyStore esta vacio.")
        else:
            # mostrar todos los aliases encontrados
            print("Aliases del KeyStore:")

            # recorrer la lista y mostrar cada alias por separado
            for alias in aliases:
                print("-", alias)

    # controlar errores de acceso o lectura del keystore
    except (ValueError, OSError) as error:
        print("Error:", error)


# ==========================================
# ========== SHOW INFORMATION ==============
# ==========================================

def show_information():
    # pedir la contrasena para acceder al keystore
    password = getpass("Contrasena del KeyStore: ")

    # pedir el alias del que se quiere consultar la informacion
    alias = input("Alias: ").strip()

    try:
        # recuperar los datos guardados para el alias indicado
        key_data = get_key(alias, password)

        # mostrar el alias, el tipo de entrada y los datos del titular guardados
        print("Alias:", alias)
        print("Tipo:", entry_type(key_data))
        print("Subject:", key_data.get("subject", "(sin datos de titular)"))

        # indicar si hay una clave privada almacenada para ese alias
        if entry_type(key_data) == "PrivateKeyEntry":
            print("Clave privada almacenada: SI")

    # controlar errores si el alias no existe o la contrasena es incorrecta
    except (ValueError, OSError) as error:
        print("Error:", error)


# ==========================================
# ============= VERIFY CSR =================
# ==========================================

def verify_csr_option():
    # pedir la ruta del archivo csr que se quiere comprobar
    filepath = input("Ruta de la CSR: ").strip()

    # comprobar que el usuario haya introducido una ruta
    if not filepath:
        print("Error: debes indicar la ruta de la CSR.")
        return

    try:
        # comprobar si la csr es valida y recuperar sus datos
        csr = verify_csr(input_path(filepath))

        # mostrar un mensaje si la verificacion se completa correctamente
        print("CSR valida correctamente.")

        # mostrar los datos del titular y la informacion de la csr
        show_csr_info(csr)

    # controlar errores de validacion o de acceso al archivo
    except (ValueError, OSError) as error:
        print("Error:", error)


# ==========================================
# ================= MAIN ===================
# ==========================================

def main():
    # mantener el menu abierto hasta que el usuario decida salir
    while True:

        # mostrar las opciones disponibles
        show_menu()

        # pedir al usuario que seleccione una opcion
        option = input("Selecciona una opcion: ").strip()

        # preparar un keystore vacio
        if option == "1":
            create_keystore_option()

        # generar un nuevo par de claves rsa
        elif option == "2":
            genkeypair()

        # mostrar los aliases guardados en el keystore
        elif option == "3":
            show_aliases()

        # consultar la informacion de un alias
        elif option == "4":
            show_information()

        # generar una solicitud csr
        elif option == "5":
            certreq()

        # verificar una solicitud csr existente
        elif option == "6":
            verify_csr_option()

        # cerrar el menu cuando el usuario seleccione la opcion 7
        elif option == "7":
            print("Saliendo de Python Keytool...")
            break

        # mostrar un error si se introduce una opcion desconocida
        else:
            print("Opcion no valida.")


# comprobar si el archivo se esta ejecutando directamente
# si se importa desde otro modulo, el menu no se inicia automaticamente
if __name__ == "__main__":
    # iniciar el menu interactivo
    main()
