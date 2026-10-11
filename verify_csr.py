
# Funciones para verificar solicitudes CSR

import os

from cryptography import x509
from cryptography.exceptions import InvalidSignature


# ==========================================
# ============== VERIFY CSR ================
# ==========================================

def verify_csr(filepath):
    # Comprobamos que el archivo exista
    if not os.path.isfile(filepath):
        raise ValueError("El archivo CSR no existe")

    try:
        with open(filepath, "rb") as file:
            csr_data = file.read()

        # Cargamos la solicitud en formato PEM
        csr = x509.load_pem_x509_csr(csr_data)

        # Comprobamos la firma de la solicitud
        if not csr.is_signature_valid:
            raise ValueError("La firma de la CSR no es valida")

        return csr

    except ValueError as error:
        if str(error) == "La firma de la CSR no es valida":
            raise
        raise ValueError("El archivo no contiene una CSR PEM valida") from error

    except (OSError, InvalidSignature) as error:
        raise ValueError("No se ha podido leer o verificar la CSR") from error


# ==========================================
# ============ SHOW CSR INFO ===============
# ==========================================

def show_csr_info(csr):
    print()
    print("===================================")
    print("          INFORMACION CSR")
    print("===================================")

    print("Subject:", csr.subject.rfc4514_string())
    print("Algoritmo:", csr.signature_hash_algorithm.name)
    print("Firma valida:", csr.is_signature_valid)
    print("Clave publica:", csr.public_key().__class__.__name__)

    print("===================================")