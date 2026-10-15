
# funciones criptograficas comunes
# contiene las funciones para generar claves rsa y crear los datos del titular

# importar x509 para trabajar con nombres y certificados digitales
from cryptography import x509

# importar los identificadores de los campos del titular
from cryptography.x509.oid import NameOID

# importar rsa para generar claves criptograficas
from cryptography.hazmat.primitives.asymmetric import rsa


# ==========================================
# =========== GENERATE RSA KEY =============
# ==========================================

def generate_rsa_key():
    # generar una clave privada rsa de 2048 bits
    # esta clave se utilizara para firmar solicitudes csr
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # exponente publico utilizado habitualmente con rsa
        key_size=2048           # tamano de la clave en bits
    )

    # devolver la clave privada generada
    return private_key


# ========================================
# =========== CREATE SUBJECT =============
# ========================================

def create_subject(cn, ou, o, l, st, c):
    # crear el distinguished name (dn) del titular
    # el dn contiene los datos que identifican a la persona o entidad

    # guardar los datos del titular utilizando sus identificadores
    # cada campo representa una parte diferente de su informacion
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, c),  # pais
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, st),  # provincia o estado
        x509.NameAttribute(NameOID.LOCALITY_NAME, l),  # localidad
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, o),  # organizacion
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),  # unidad organizativa
        x509.NameAttribute(NameOID.COMMON_NAME, cn),  # nombre comun del titular
    ])

    # devolver el dn creado para utilizarlo en la solicitud csr
    return subject


# ==========================================
# ============== TEST MANUAL ===============
# ==========================================

# comprobar si este archivo se esta ejecutando directamente
# si se importa desde otro archivo, este bloque no se ejecuta
if __name__ == "__main__":
    # generar una nueva clave privada rsa
    private_key = generate_rsa_key()

    # mostrar un mensaje para confirmar que la clave se ha generado
    print("Clave RSA generada correctamente.")

    # mostrar el tamano de la clave generada en bits
    print("Tamaño:", private_key.key_size, "bits")