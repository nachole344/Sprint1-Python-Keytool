
# funciones criptograficas comunes
# contiene las funciones para generar claves rsa, crear los datos del titular
# y crear certificados (autofirmados o firmados a partir de una csr)

import datetime
import re

# importar x509 para trabajar con nombres y certificados digitales
from cryptography import x509

# importar los identificadores de los campos del titular
from cryptography.x509.oid import NameOID

# importar rsa para generar claves criptograficas
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# ==========================================
# =========== GENERATE RSA KEY =============
# ==========================================

def generate_rsa_key(key_size=2048):
    # generar una clave privada rsa (por defecto de 2048 bits)
    # esta clave se utilizara para firmar solicitudes csr y certificados
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # exponente publico utilizado habitualmente con rsa
        key_size=key_size       # tamano de la clave en bits
    )

    # devolver la clave privada generada
    return private_key


def load_private_key(private_key_pem, key_password):
    # convertir el texto pem cifrado en un objeto de clave privada
    # la clave esta cifrada con la contraseña del alias
    try:
        return serialization.load_pem_private_key(
            private_key_pem.encode("ascii"),
            password=key_password.encode("utf-8")
        )
    except ValueError as error:
        raise ValueError("Contraseña del alias incorrecta o clave dañada") from error
    except TypeError as error:
        raise ValueError("La clave guardada no está cifrada con contraseña") from error


def private_key_to_pem(private_key, key_password):
    # guardar la clave privada en pem (pkcs8) cifrada con la contraseña del alias
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            key_password.encode("utf-8")
        )
    ).decode("ascii")


# ========================================
# =========== CREATE SUBJECT =============
# ========================================

def create_subject(cn, ou, o, l, st, c):
    subject = []

    if c != "Unknown":
        subject.append(x509.NameAttribute(NameOID.COUNTRY_NAME, c))

    subject.extend([
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, st),
        x509.NameAttribute(NameOID.LOCALITY_NAME, l),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, o),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
        x509.NameAttribute(NameOID.COMMON_NAME, cn)
    ])

    return x509.Name(subject)


def parse_dname(text):
    # convertir un texto como "CN=Ana, OU=DAM, O=CETI, C=ES" (opcion -dname) en un dn
    # se separa por las comas que no estan escapadas con barra invertida
    parts = [part.strip() for part in re.split(r"(?<!\\),", text) if part.strip()]

    if not parts:
        raise ValueError("El DN no puede estar vacío")

    # los nombres de los campos (cn, ou...) se pasan a mayusculas
    fixed_parts = []
    for part in parts:
        if "=" not in part:
            raise ValueError(f"DN no válido: {text}")
        name, value = part.split("=", 1)
        fixed_parts.append(name.strip().upper() + "=" + value)

    try:
        return x509.Name.from_rfc4514_string(",".join(fixed_parts))
    except ValueError as error:
        raise ValueError(f"DN no válido: {text}") from error


# ==========================================
# ============ CERTIFICATES ================
# ==========================================

def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def create_self_signed_certificate(private_key, subject, days=90):
    # certificado autofirmado: el titular y el emisor son el mismo
    # se firma con la propia clave privada (igual que hace keytool -genkeypair)
    now = _now()

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days))
        .sign(private_key, hashes.SHA256())
    )

    return certificate


def issue_certificate(csr, issuer_key, issuer_certificate, days=90):
    # certificado emitido a partir de una csr (keytool -gencert)
    # los datos del titular y su clave publica salen de la csr
    # el emisor es el dueño de issuer_key y firma con su clave privada
    now = _now()

    certificate = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer_certificate.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days))
        .sign(issuer_key, hashes.SHA256())
    )

    return certificate
