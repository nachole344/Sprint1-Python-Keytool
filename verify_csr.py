# Para trabajar con archivos
import os

# Libreria cryptography
from cryptography import x509


# ==========================================
# ============== VERIFY CSR ================
# ==========================================

def verify_csr(filepath):

    # Comprobamos que exista
    if not os.path.exists(filepath):
        raise ValueError(
            "El archivo CSR no existe"
        )

    # Leemos el archivo
    with open(
        filepath,
        "rb"
    ) as file:

        csr_data = file.read()

    try:

        # Cargamos la CSR
        csr = x509.load_pem_x509_csr(
            csr_data
        )

    except ValueError:

        raise ValueError(
            "El archivo no contiene una CSR valida"
        )

    # Comprobamos firma
    if not csr.is_signature_valid:

        raise ValueError(
            "La firma de la CSR no es valida"
        )

    return csr


# ==========================================
# ============ SHOW CSR INFO ===============
# ==========================================

def show_csr_info(csr):

    print()
    print("===================================")
    print("          INFORMACION CSR")
    print("===================================")

    print(
        "Subject:",
        csr.subject.rfc4514_string()
    )

    print(
        "Algoritmo:",
        csr.signature_hash_algorithm.name
    )

    print(
        "Firma valida:",
        csr.is_signature_valid
    )

    print(
        "Clave publica:",
        csr.public_key().__class__.__name__
    )

    print("===================================")