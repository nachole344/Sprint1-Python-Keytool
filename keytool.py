
# Simulador de Java Keytool en Python

import argparse
from getpass import getpass

from crypto_utils import generate_rsa_key, create_subject
from keystore import save_key, get_key
from csr import generate_csr_for_alias, save_csr


# ==========================================
# ============== GENKEYPAIR =================
# ==========================================

def genkeypair():
    print("=== Generacion de par de claves ===")

    password = getpass("Contrasena del KeyStore: ")
    if not password:
        print("Error: la contrasena no puede estar vacia.")
        return

    alias = input("Alias: ").strip()
    if not alias:
        print("Error: el alias no puede estar vacio.")
        return

    print("\n=== Datos del titular ===")

    cn = input("CN (Common Name): ").strip()
    ou = input("OU (Organizational Unit): ").strip()
    o = input("O (Organization): ").strip()
    l = input("L (Locality): ").strip()
    st = input("ST (State/Province): ").strip()
    c = input("C (Country, 2 letras): ").strip().upper()

    fields = [cn, ou, o, l, st, c]

    if any(not value for value in fields):
        print("Error: todos los campos del titular son obligatorios.")
        return

    if len(c) != 2 or not c.isalpha() or not c.isascii():
        print("Error: C debe contener dos letras ASCII.")
        return

    try:
        # Generamos la clave RSA
        private_key = generate_rsa_key()

        # Creamos el DN
        subject = create_subject(cn, ou, o, l, st, c)

        # Guardamos la clave en el KeyStore cifrado
        save_key(alias, private_key, subject, password)

        print("\nPar de claves generado y guardado correctamente.")
        print("Alias:", alias)
        print("Tamano RSA:", private_key.key_size, "bits")
        print("DN:", subject.rfc4514_string())

    except (ValueError, OSError) as error:
        print("Error:", error)


# ==========================================
# ================ CERTREQ =================
# ==========================================

def certreq():
    print("=== Generacion de solicitud CSR ===")

    password = getpass("Contrasena del KeyStore: ")
    if not password:
        print("Error: la contrasena no puede estar vacia.")
        return

    alias = input("Alias de la clave: ").strip()
    if not alias:
        print("Error: el alias no puede estar vacio.")
        return

    try:
        # Comprobamos que el alias se pueda recuperar
        get_key(alias, password)

        # Generamos la CSR utilizando la clave y el DN guardados
        csr = generate_csr_for_alias(alias, password)

        # Guardamos la CSR en formato PEM
        filepath = save_csr(csr, alias + ".csr")

        print("\nCSR generada correctamente.")
        print("Archivo:", filepath)
        print("Formato: PEM")

    except (ValueError, OSError) as error:
        print("Error:", error)


# ==========================================
# ================= MAIN ===================
# ==========================================

def main():
    parser = argparse.ArgumentParser(
        description="Simulacion de Java Keytool en Python"
    )

    commands = parser.add_mutually_exclusive_group()

    commands.add_argument(
        "--genkeypair",
        action="store_true",
        help="Genera y guarda un par de claves RSA de 2048 bits"
    )

    commands.add_argument(
        "--certreq",
        action="store_true",
        help="Genera una solicitud CSR en formato PEM"
    )

    args = parser.parse_args()

    if args.genkeypair:
        genkeypair()
    elif args.certreq:
        certreq()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()