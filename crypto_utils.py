# Funciones criptograficas comunes

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa

# ==========================================
# =========== GENERATE RSA KEY =============
# ==========================================


def generate_rsa_key():
    #genera una clave privada RSA de 2048 bits
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    return private_key



# ========================================
# =========== CREATE SUBJECT =============
# ========================================
def create_subject(cn, ou, o, l, st, c):
#crea el sdtinguished name DN del titulae
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, c),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, st),
        x509.NameAttribute(NameOID.LOCALITY_NAME, l),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, o),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    return subject

# ==========================================
# ============== TEST MANUAL ===============
# ==========================================
if __name__ == "__main__":
    private_key = generate_rsa_key()

    print("Clave RSA generada correctamente.")
    print("Tamaño:", private_key.key_size, "bits")