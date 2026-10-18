
# funciones para leer, mostrar y guardar certificados y listas de revocacion (crl)

import hashlib

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# ==========================================
# ============ LEER ARCHIVOS ===============
# ==========================================

def _read_file(filepath, kind):
    try:
        with open(filepath, "rb") as file:
            return file.read()
    except FileNotFoundError as error:
        raise ValueError(f"El archivo {kind} no existe: {filepath}") from error
    except OSError as error:
        raise ValueError(f"No se ha podido leer el archivo {kind}: {filepath}") from error


def load_certificate_file(filepath):
    # un certificado puede estar en PEM (texto) o en DER (binario)
    content = _read_file(filepath, "del certificado")

    try:
        return x509.load_pem_x509_certificate(content)
    except ValueError:
        pass

    try:
        return x509.load_der_x509_certificate(content)
    except ValueError as error:
        raise ValueError("El archivo no contiene un certificado válido (PEM o DER)") from error


def load_certificate_pem(pem_text):
    return x509.load_pem_x509_certificate(pem_text.encode("ascii"))


def load_crl_file(filepath):
    content = _read_file(filepath, "de la CRL")

    try:
        return x509.load_pem_x509_crl(content)
    except ValueError:
        pass

    try:
        return x509.load_der_x509_crl(content)
    except ValueError as error:
        raise ValueError("El archivo no contiene una CRL válida (PEM o DER)") from error


def write_certificate(certificate, filepath, rfc=False):
    # por defecto se guarda en DER (binario) como keytool; con -rfc se guarda en PEM
    encoding = serialization.Encoding.PEM if rfc else serialization.Encoding.DER

    with open(filepath, "wb") as file:
        file.write(certificate.public_bytes(encoding))


# ==========================================
# ============== COMPROBACIONES ============
# ==========================================

def fingerprint_sha256(certificate):
    # la huella es el hash sha-256 del certificado (un hash no se puede revertir)
    digest = hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def is_signed_by(certificate, issuer):
    # comprobar con la clave publica del emisor que la firma del certificado es correcta
    try:
        certificate.verify_directly_issued_by(issuer)
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


def is_self_signed(certificate):
    return is_signed_by(certificate, certificate)


def same_public_key(certificate, public_key_pem):
    # comparar la clave publica de un certificado con la guardada en una entrada
    stored = serialization.load_pem_public_key(public_key_pem.encode("ascii"))

    def to_der(key):
        return key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

    return to_der(certificate.public_key()) == to_der(stored)


def key_description(public_key):
    if isinstance(public_key, rsa.RSAPublicKey):
        return f"RSA {public_key.key_size} bits"

    return type(public_key).__name__


# ==========================================
# ============== MOSTRAR ===================
# ==========================================

def show_certificate_info(certificate, indent=""):
    hash_algorithm = certificate.signature_hash_algorithm
    algorithm = hash_algorithm.name if hash_algorithm else "desconocido"

    print(f"{indent}Titular: {certificate.subject.rfc4514_string()}")
    print(f"{indent}Emisor: {certificate.issuer.rfc4514_string()}")
    print(f"{indent}Número de serie: {certificate.serial_number:x}")
    print(f"{indent}Válido desde: {certificate.not_valid_before_utc:%Y-%m-%d %H:%M} UTC"
          f" hasta: {certificate.not_valid_after_utc:%Y-%m-%d %H:%M} UTC")
    print(f"{indent}Algoritmo de firma: {algorithm} con RSA")
    print(f"{indent}Clave pública: {key_description(certificate.public_key())}")
    print(f"{indent}Huella SHA-256: {fingerprint_sha256(certificate)}")

    if is_self_signed(certificate):
        print(f"{indent}Autofirmado: sí (firma comprobada con su propia clave pública)")
    else:
        print(f"{indent}Autofirmado: no (hace falta el certificado del emisor para comprobar su firma)")


def show_crl_info(crl):
    print(f"Emisor: {crl.issuer.rfc4514_string()}")
    print(f"Última actualización: {crl.last_update_utc:%Y-%m-%d %H:%M} UTC")

    if crl.next_update_utc:
        print(f"Próxima actualización: {crl.next_update_utc:%Y-%m-%d %H:%M} UTC")

    revoked = list(crl)
    print(f"Certificados revocados: {len(revoked)}")

    for item in revoked:
        print(f"  - serie {item.serial_number:x}, revocado el {item.revocation_date_utc:%Y-%m-%d %H:%M} UTC")

    print("Nota: no se ha comprobado la firma de la CRL (no se dispone del certificado del emisor).")
