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
# ============== CREATE SUBJECT ============
# ==========================================

def create_subject(
    common_name,
    organizational_unit,
    organization,
    locality,
    state,
    country
):

    subject = x509.Name([
        x509.NameAttribute(
            NameOID.COUNTRY_NAME,
            country
        ),

        x509.NameAttribute(
            NameOID.STATE_OR_PROVINCE_NAME,
            state
        ),

        x509.NameAttribute(
            NameOID.LOCALITY_NAME,
            locality
        ),

        x509.NameAttribute(
            NameOID.ORGANIZATION_NAME,
            organization
        ),

        x509.NameAttribute(
            NameOID.ORGANIZATIONAL_UNIT_NAME,
            organizational_unit
        ),

        x509.NameAttribute(
            NameOID.COMMON_NAME,
            common_name
        )
    ])

    return subject


# ==========================================
# ============== GENERATE CSR ==============
# ==========================================

def generate_csr_for_alias(
    alias,
    password,
    common_name,
    organizational_unit,
    organization,
    locality,
    state,
    country
):

    # Recuperamos los datos del alias
    key_data = get_key(
        alias,
        password
    )

    # Recuperamos clave privada PEM
    private_key_pem = key_data[
        "private_key"
    ]

    # Convertimos PEM a clave privada
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None
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

    # Creamos CSR
    csr_builder = (
        x509.CertificateSigningRequestBuilder()
    )

    csr_builder = csr_builder.subject_name(
        subject
    )

    # Firmamos CSR
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