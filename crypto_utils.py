from crypto_utils import generate_rsa_key, create_subject

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