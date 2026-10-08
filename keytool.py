import argparse
from getpass import getpass
from crypto_utils import generate_rsa_key, create_subject

def genkeypair():

    print("=== Generación de par de claves ===")

    password = getpass("Contraseña del KeyStore: ")

    if not password:
        print("Error: la contraseña no puede estar vacía.")
        return

    alias = input("Alias: ").strip()

    if not alias:
        print("Error: el alias no puede estar vacío.")
        return

    cn = input("CN (Common Name): ").strip()
    ou = input("OU (Organizational Unit): ").strip()
    o = input("O (Organization): ").strip()
    l = input("L (Locality): ").strip()
    st = input("ST (State/Province): ").strip()
    c = input("C (Country): ").strip().upper()

    if len(c) != 2:
        print("Error: C debe tener exactamente 2 caracteres.")
        return

    private_key = generate_rsa_key()

    subject = create_subject(
        cn=cn,
        ou=ou,
        o=o,
        l=l,
        st=st,
        c=c
    )

    print()
    print("Par de claves RSA generado correctamente.")
    print(f"Alias: {alias}")
    print(f"Tamaño de clave: {private_key.key_size} bits")
    print(f"DN: {subject.rfc4514_string()}")

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
        print("Comando --certreq seleccionado.") # Mensaje temporal

    else: # Si no se proporcionan argumentos, mostrar ayuda
        parser.print_help()



if __name__ == "__main__":
    main()