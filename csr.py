
# Funciones para generar y guardar solicitudes CSR

import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from keystore import get_key


# ==========================================
# ============== CREATE SUBJECT =============
# ==========================================

def create_subject(
    common_name,
    organizational_unit,
    organization,
    locality,
    state,
    country
):
    # Creamos el DN con los seis campos del titular
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name)
    ])


# ==========================================
# ============== GENERATE CSR ==============
# ==========================================

def generate_csr_for_alias(alias, password):
    # Recuperamos la informacion de la clave guardada
    key_data = get_key(alias, password)

    private_key_pem = key_data["private_key"]
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("ascii"),
        password=None
    )

    # Recuperamos el DN original del almacen
    subject_data = key_data["subject"]
    subject = x509.Name.from_rfc4514_string(subject_data)

    # Creamos la solicitud de firma
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, hashes.SHA256())
    )

    return csr


# ==========================================
# ================ SAVE CSR ================
# ==========================================

def save_csr(csr, filename):
    data_dir = "data"
    os.makedirs(data_dir, exist_ok=True)

    # Evitamos rutas arbitrarias en el nombre del archivo
    filename = os.path.basename(filename)

    if not filename.lower().endswith(".csr"):
        filename += ".csr"

    filepath = os.path.join(data_dir, filename)

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    with open(filepath, "wb") as file:
        file.write(csr_pem)

    return filepath