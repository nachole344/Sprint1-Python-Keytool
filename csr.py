# Para trabajar con archivos
import os

# Librerias de cryptography
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

# Funcion para recuperar claves
from keystore import get_key

# ==========================================
# ============== GENERATE CSR ==============
# ==========================================

def generate_csr_for_alias(alias, password):

    # Recuperamos los datos del alias desde el KeyStore
    key_data = get_key(
        alias,
        password
    )

    # Recuperamos la clave privada PEM
    private_key_pem = key_data["private_key"]

    # Convertimos PEM a objeto de clave privada
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None
    )

    # Recuperamos el Subject almacenado en el KeyStore
    subject_string = key_data["subject"]

    # Convertimos la cadena RFC4514 a objeto x509.Name
    subject = x509.Name.from_rfc4514_string(
        subject_string
    )

    # Creamos el constructor de la CSR
    csr_builder = x509.CertificateSigningRequestBuilder()

    # Establecemos el Subject
    csr_builder = csr_builder.subject_name(
        subject
    )

    # Firmamos la CSR con la clave privada
    csr = csr_builder.sign(
        private_key,
        hashes.SHA256()
    )

    return csr


# ==========================================
# ================ SAVE CSR ================
# ==========================================

def save_csr(csr, filename):

    data_dir = "data"

    if not os.path.exists(data_dir):
        os.makedirs(data_dir)

    filepath = os.path.join(
        data_dir,
        filename
    )

    csr_pem = csr.public_bytes(
        serialization.Encoding.PEM
    )

    with open(
        filepath,
        "wb"
    ) as file:

        file.write(csr_pem)

    return filepath