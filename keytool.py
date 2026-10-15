import argparse
from getpass import getpass

from crypto_utils import generate_rsa_key, create_subject
from keystore import save_key, keystore_exists, alias_exists
from csr import generate_csr_for_alias, save_csr
from verify_csr import verify_csr, show_csr_info


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
    commands.add_argument(
        "--printcertreq",
        metavar="ARCHIVO",
        help="Verifica y muestra la información de un archivo CSR"
    )

    args = parser.parse_args()

    if args.genkeypair:
        genkeypair()
    elif args.certreq:
        certreq()
    elif args.printcertreq:
        printcertreq(args.printcertreq)
    else:
        parser.print_help()


def genkeypair():
    print("=== Generación de par de claves ===")

    # si el almacen es nuevo se pide confirmar la contraseña
    password = ask_password(confirm=not keystore_exists())
    if not password:
        return

    alias = ask_alias()
    if not alias:
        return

    # comprobar contraseña y alias antes de pedir mas datos y generar la clave
    if keystore_exists():
        try:
            if alias_exists(alias, password):
                print("Error: el alias ya existe")
                return
        except ValueError as error:
            print(f"Error: {error}")
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
        save_key(alias, private_key, subject, password)
    except (ValueError, OSError) as error:
        print(f"Error: {error}")
        return

    print()
    print("Par de claves RSA generado correctamente.")
    print(f"Alias: {alias}")
    print(f"Tamaño de clave: {private_key.key_size} bits")
    print(f"DN: {subject.rfc4514_string()}")
    print("Clave guardada correctamente en el KeyStore.")


def ask_password(confirm=False):
    password = getpass("Contraseña del KeyStore: ")

    if not password:
        print("Error: la contraseña no puede estar vacía.")
        return None

    if confirm:
        if getpass("Repite la contraseña: ") != password:
            print("Error: las contraseñas no coinciden.")
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

    fields = {
        "CN": input("CN (Common Name): ").strip(),
        "OU": input("OU (Organizational Unit): ").strip(),
        "O": input("O (Organization): ").strip(),
        "L": input("L (Locality): ").strip(),
        "ST": input("ST (State/Province): ").strip(),
        "C": input("C (Country): ").strip().upper(),
    }

    for name, value in fields.items():
        if not value:
            print(f"Error: el campo {name} no puede estar vacío.")
            return None

    if len(fields["C"]) != 2:
        print("Error: el campo C debe tener exactamente 2 caracteres.")
        return None

    return fields


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

        csr = generate_csr_for_alias(alias, password)
        filepath = save_csr(csr, alias + ".csr")

        print()
        print("CSR generada correctamente.")
        print("Archivo:", filepath)

    except FileNotFoundError as error:
        # el KeyStore todavia no existe
        print(f"Error: {error}")

    except (ValueError, OSError) as error:
        print(f"Error: {error}")

    except (TypeError, KeyError):
        print("Error: los datos almacenados en el KeyStore no son válidos.")


def printcertreq(filepath):
    try:
        csr = verify_csr(filepath)
    except ValueError as error:
        print(f"Error: {error}")
        return

    show_csr_info(csr)


if __name__ == "__main__":
    main()