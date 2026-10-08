import argparse
from getpass import getpass
from crypto_utils import generate_rsa_key, create_subject
from keystore import save_key
from csr import generate_csr_for_alias, save_csr

# Función principal del script
def main():

    parser = argparse.ArgumentParser(
        description="Simulación de Java Keytool en Python"
    )

    commands = parser.add_mutually_exclusive_group()

    commands.add_argument(
        "--genkeypair",
        action="store_true",
        help="Genera un par de claves RSA de 2048 bits"
    )

    commands.add_argument(
        "--certreq",
        action="store_true",
        help="Genera una solicitud de firma de certificado (CSR)"
    )

    args = parser.parse_args()

    if args.genkeypair:
        genkeypair()

    elif args.certreq:
        certreq()

    else: # Si no se proporcionan argumentos, mostrar ayuda
        parser.print_help()

# Funciones del comando genkeypair
def genkeypair():

    print("=== Generación de par de claves ===")

    password = ask_password()
    if not password:
        return

    alias = ask_alias()
    if not alias:
        return

    subject_data = ask_subject_data()
    if not subject_data:
        return

    private_key = generate_rsa_key()

    subject = create_subject(
        cn=subject_data["CN"],
        ou=subject_data["OU"],
        o=subject_data["O"],
        l=subject_data["L"],
        st=subject_data["ST"],
        c=subject_data["C"]
    )

    try:
        save_key(
            alias,
            private_key,
            subject,
            password
        )

    except ValueError as error:
        print(f"Error: {error}")
        return

    print()
    print("Par de claves RSA generado correctamente.")
    print(f"Alias: {alias}")
    print(f"Tamaño de clave: {private_key.key_size} bits")
    print(f"DN: {subject.rfc4514_string()}")
    print("Clave guardada correctamente en el KeyStore.")

def ask_password():
    password = getpass("Contraseña del KeyStore: ")

    if not password:
        print("Error: la contraseña no puede estar vacía.")
        return None

    return password

def ask_alias():

    alias = input("Alias: ").strip()

    if not alias:
        print("Error: el alias no puede estar vacío.")
        return None

    return alias

def ask_subject_data():
    print("\n=== Datos del titular ===")

    cn = input("CN (Common Name): ").strip()
    ou = input("OU (Organizational Unit): ").strip()
    o = input("O (Organization): ").strip()
    l = input("L (Locality): ").strip()
    st = input("ST (State/Province): ").strip()
    c = input("C (Country): ").strip().upper()

    fields = {
        "CN": cn,
        "OU": ou,
        "O": o,
        "L": l,
        "ST": st,
        "C": c
    }

    for name, value in fields.items():
        if not value:
            print(f"Error: el campo {name} no puede estar vacío.")
            return None

    if len(c) != 2:
        print("Error: el campo C debe tener exactamente 2 caracteres.")
        return None

    return fields

# Funciones del comando certreq
def certreq():
    print("=== Generación de solicitud de firma de certificado (CSR) ===")

    password = ask_password()
    if not password:
        return

    alias = ask_alias()
    if not alias:
        return

    try:
        print()
        print("Recuperando clave del KeyStore...")

        csr = generate_csr_for_alias(
            alias,
            password
        )

        filename = alias + ".csr"

        filepath = save_csr(
            csr,
            filename
        )

        print()
        print("CSR generada correctamente.")
        print("Archivo:", filepath)

    except ValueError as error:
        print(f"Error: {error}")

    except (TypeError, KeyError):
        print("Error: los datos almacenados en el KeyStore no son válidos.")

# Bloque principal
if __name__ == "__main__":
    main()