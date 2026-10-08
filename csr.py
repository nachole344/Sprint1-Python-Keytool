#se encarga de generar CSR
# solo recibe datos que necesita y lo genera
#necesita la clave privada * subject/dn

#para trabajar con archivos, carñpetas, certificasos y csr, identificar campos del subject, trbahar con claves privadas, comprobar q CSR es valido, algortmos hash
import os

from cryptography import x509m 
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

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
            country
        ),
    ])

    return subject




#====================
#========SAVE========
#====================
#separar la generacion y el guardado
#recibe el csr y el filename
save_csr()


#========================
#========GENERATE========
#========================
#recibe el private_key y el subject para devolver el CSR
#dsp de crearla crea el archivo .csr
#ese deveria tener :-----BEGIN CERTIFICATE REQUEST-----
#-----END CERTIFICATE REQUEST-----
generate_csr()



