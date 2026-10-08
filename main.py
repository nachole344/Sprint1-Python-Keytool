# Para introducir contraseñas sin mostrarlas
from getpass import getpass

# Para generar claves RSA
from cryptography.hazmat.primitives.asymmetric import rsa

# Funciones del KeyStore
from keystore import (
    create_keystore,
    save_key,
    get_key,
    alias_exists,
    list_aliases
)

# Funciones de CSR
from csr import (
    create_subject,
    generate_csr_for_alias,
    save_csr
)

# Funciones de verificacion
from verify_csr import (
    verify_csr,
    show_csr_info
)


# ==========================================
# ============== PASSWORD ==================
# ==========================================

def ask_password():

    password = getpass(
        "Introduce la contraseña del KeyStore: "
    )

    return password


# ==========================================
# ================ MENU ====================
# ==========================================

def show_menu():

    print()
    print("===================================")
    print("          PYTHON KEYTOOL")
    print("===================================")
    print("1. Crear KeyStore")
    print("2. Generar clave")
    print("3. Listar aliases")
    print("4. Mostrar informacion")
    print("5. Generar CSR")
    print("6. Verificar CSR")
    print("7. Salir")
    print("===================================")


# ==========================================
# =========== CREATE KEYSTORE ==============
# ==========================================

def create_keystore_option():

    print()
    print("========== CREAR KEYSTORE ==========")

    password = ask_password()

    create_keystore()

    # Comprobamos si ya existe
    aliases = list_aliases(password)

    print()
    print("KeyStore preparado correctamente.")
    print("Aliases:", len(aliases))


# ==========================================
# ============ GENERATE KEY ================
# ==========================================

def generate_key():

    print()
    print("========== GENERAR CLAVE ==========")

    password = ask_password()

    alias = input(
        "Alias: "
    )

    # Comprobamos alias
    if alias_exists(
        alias,
        password
    ):

        print(
            "Error: el alias ya existe."
        )

        return

    print()
    print("Datos del certificado:")

    common_name = input(
        "Common Name: "
    )

    organizational_unit = input(
        "Unidad organizativa: "
    )

    organization = input(
        "Organizacion: "
    )

    locality = input(
        "Localidad: "
    )

    state = input(
        "Provincia: "
    )

    country = input(
        "Pais: "
    )

    print()
    print("Generando clave RSA...")

    # Generamos RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Creamos Subject
    subject = create_subject(
        common_name,
        organizational_unit,
        organization,
        locality,
        state,
        country
    )

    # Guardamos clave
    save_key(
        alias,
        private_key,
        subject,
        password
    )

    print()
    print("Clave generada correctamente.")
    print("Alias:", alias)


# ==========================================
# ============ LIST ALIASES ================
# ==========================================

def show_aliases():

    print()
    print("========== LISTA DE ALIASES ==========")

    password = ask_password()

    try:

        aliases = list_aliases(
            password
        )

        if not aliases:

            print("El KeyStore esta vacio.")
            return

        print()

        for alias in aliases:

            print(
                "-",
                alias
            )

    except ValueError as error:

        print(
            "Error:",
            error
        )


# ==========================================
# =========== SHOW INFORMATION ============
# ==========================================

def show_information():

    print()
    print("========== INFORMACION ==========")

    password = ask_password()

    alias = input(
        "Alias: "
    )

    try:

        key_data = get_key(
            alias,
            password
        )

        print()
        print("Alias:", alias)
        print(
            "Subject:",
            key_data["subject"]
        )

        print(
            "Clave privada almacenada: SI"
        )

    except ValueError as error:

        print(
            "Error:",
            error
        )


# ==========================================
# ============ GENERATE CSR ================
# ==========================================

def generate_csr():

    print()
    print("========== GENERAR CSR ==========")

    password = ask_password()

    alias = input(
        "Alias: "
    )

    try:

        if not alias_exists(
            alias,
            password
        ):

            print(
                "Error: el alias no existe."
            )

            return

        common_name = input(
            "Common Name: "
        )

        organizational_unit = input(
            "Unidad organizativa: "
        )

        organization = input(
            "Organizacion: "
        )

        locality = input(
            "Localidad: "
        )

        state = input(
            "Provincia: "
        )

        country = input(
            "Pais: "
        )

        print()
        print("Generando CSR...")

        csr = generate_csr_for_alias(
            alias,
            password,
            common_name,
            organizational_unit,
            organization,
            locality,
            state,
            country
        )

        filename = alias + ".csr"

        filepath = save_csr(
            csr,
            filename
        )

        print()
        print("CSR generada correctamente.")
        print(
            "Archivo:",
            filepath
        )

    except ValueError as error:

        print(
            "Error:",
            error
        )


# ==========================================
# ============= VERIFY CSR =================
# ==========================================

def verify_csr_option():

    print()
    print("========== VERIFICAR CSR ==========")

    filepath = input(
        "Ruta de la CSR: "
    )

    if filepath == "":

        filepath = "data/pepe.csr"

    try:

        csr = verify_csr(
            filepath
        )

        print()
        print(
            "CSR valida correctamente."
        )

        show_csr_info(
            csr
        )

    except ValueError as error:

        print(
            "Error:",
            error
        )


# ==========================================
# ================ MAIN ====================
# ==========================================

def main():

    while True:

        show_menu()

        option = input(
            "Selecciona una opcion: "
        )

        if option == "1":

            create_keystore_option()

        elif option == "2":

            try:
                generate_key()

            except ValueError as error:

                print(
                    "Error:",
                    error
                )

        elif option == "3":

            show_aliases()

        elif option == "4":

            show_information()

        elif option == "5":

            generate_csr()

        elif option == "6":

            verify_csr_option()

        elif option == "7":

            print()
            print(
                "Saliendo de Python Keytool..."
            )

            break

        else:

            print()
            print(
                "Opcion no valida."
            )


# ==========================================
# ================ START ===================
# ==========================================

if __name__ == "__main__":

    main()