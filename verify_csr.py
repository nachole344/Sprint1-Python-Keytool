# funciones para verificar solicitudes csr y mostrar su informacion
# tambien se puede usar desde la terminal: python verify_csr.py archivo.csr
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def verify_csr(filepath):
    if not os.path.isfile(filepath):
        raise ValueError("El archivo CSR no existe")

    try:
        with open(filepath, "rb") as file:
            csr_data = file.read()
    except OSError as error:
        raise ValueError("No se ha podido leer la CSR") from error

    try:
        csr = x509.load_pem_x509_csr(csr_data)
    except ValueError as error:
        raise ValueError("El archivo no contiene una CSR PEM valida") from error

    # is_signature_valid es una propiedad: devuelve True/False, no lanza excepcion
    # comprueba que la csr esta firmada con la clave privada que corresponde a su clave publica
    if not csr.is_signature_valid:
        raise ValueError("La firma de la CSR no es valida")

    return csr


def show_csr_info(csr):
    public_key = csr.public_key()

    if isinstance(public_key, rsa.RSAPublicKey):
        key_info = f"RSA {public_key.key_size} bits"
    else:
        key_info = type(public_key).__name__

    print()
    print("===================================")
    print("          INFORMACION CSR")
    print("===================================")
    print("Subject:", csr.subject.rfc4514_string())
    country = csr.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
    print("Country:", country[0].value if country else "Unknown")
    hash_algorithm = csr.signature_hash_algorithm
    print("Algoritmo:", hash_algorithm.name if hash_algorithm else "desconocido")
    print("Firma valida:", csr.is_signature_valid)
    print("Clave publica:", key_info)
    print("===================================")


def main(argv=None):
    # uso desde la terminal: python verify_csr.py archivo.csr
    argv = sys.argv[1:] if argv is None else argv

    if len(argv) != 1 or argv[0] in ("-h", "--help", "-?"):
        print("Uso: python verify_csr.py ARCHIVO.csr")
        print("Comprueba que el archivo es una CSR (PEM) con firma valida y muestra su informacion.")
        return 0 if argv and argv[0] in ("-h", "--help", "-?") else 1

    try:
        csr = verify_csr(argv[0])
    except ValueError as error:
        print(f"Error: {error}")
        return 1

    print("CSR valida correctamente.")
    show_csr_info(csr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
