#se encarga de generar CSR
# solo recibe datos que necesita y lo genera
#necesita la clave privada * subject/dn

#para trabajar con archivos, carñpetas, certificasos y csr, identificar campos del subject, trbahar con claves privadas, comprobar q CSR es valido, algortmos hash
import os

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


#==============================
#========CREATE_SUBJECT========
#==============================
#crea el subject que se unsa en el csr
def create_subject(common_name, organizational_unit, organization, locality, state, country):

    subject = x509.Name([
        x509.NameAttribute(
            NameOID.COMMON_NAME,
            common_name
        ),

        x509.NameAttribute(
            NameOID.ORGANIZATIONAL_UNIT_NAME,
            organizational_unit
        ),

        x509.NameAttribute(
            NameOID.ORGANIZATION_NAME,
            organization
        ),

        x509.NameAttribute(
            NameOID.LOCALITY_NAME,
            locality
        ),

        x509.NameAttribute(
            NameOID.STATE_OR_PROVINCE_NAME,
            state
        ),

        x509.NameAttribute(
            NameOID.COUNTRY_NAME,
            country
        )
    ])

    return subject

#======================
#========CREATE========
#======================
#crea wl CSR recibe el private_key y el subject y devuelve el csr
def create_csr(private_key, subject):
    #crea el builder del CSR
    builder = x509.CertificateSigningRequestBuilder()

    #añade el subject
    builder = builder.subject_name(subject)

    #firmar el csr con la clave privada
    csr = builder.sign(
        private_key,
        algorithm=hashes.SHA256()
    )
    return csr



#====================
#========SAVE========
#====================
#separar la generacion y el guardado
#recibe el csr y el filename
#guarda un csr en formato PEM
def save_csr(csr, filename):
    csr_dir = os.path.join("data", "csr")

    if not os.path.exists(csr_dir):
        os.makedirs(csr_dir)

    filepath = os.path.join(csr_dir, filename)

    csr_pem = csr.public_bytes(
        serialization.Encoding.PEM
    )

    with open(filepath, "wb") as file:
        file.write(csr_pem)

    return filepath

#====================
#========LOAD========
#====================
#carga un csr desde un archivo PEM
def load_csr(filename):
    csr_dir = os.path.join("data", "csr")
    filepath = os.path.join(csr_dir, filename)

    if not os.path.exists(filepath):
        raise FileNotFoundError("el CSR no existe")

    with open(filepath, "rb") as file:
        csr_data = file.read()

    try: 
        csr = x509.load_pem_x509_csr(csr_data)

    except ValueError:
        raise ValueError("el CSr no tiene formato valido")
    
    return csr

#========================
#========VALIDATE========
#========================
#copmprueba que el CSR tiene firma valida
def validate_csr(csr):
    try:
        public_key = csr.public_key()

        public_key.verify(
            csr.signature,
            csr.tbs_certrequest_bytes,
            padding.PKCS1v15(),
            csr.signature_hash_algorithm
        )

        return True

    except Exception:
        return False


