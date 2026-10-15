# funciones para verificar solicitudes csr y mostrar su informacion
import os

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa


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
    print("Algoritmo:", csr.signature_hash_algorithm.name)
    print("Firma valida:", csr.is_signature_valid)
    print("Clave publica:", key_info)
    print("===================================")