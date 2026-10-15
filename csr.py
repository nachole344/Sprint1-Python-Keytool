
# funciones para generar y guardar solicitudes csr
# una csr es una solicitud de firma de certificado digital

# importar os para trabajar con archivos y carpetas
import os

# importar las funciones necesarias para crear solicitudes y certificados
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

# importar la funcion para recuperar una clave del keystore
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
    # crear el DN con los seis campos del titular
    # el DN contiene la informacion de la persona o entidad
    # a la que pertenece el certificado

    # guardar los datos del titular utilizando sus identificadores
    # cada campo representa una parte diferente de su informacion
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
    # recuperar la informacion de la clave guardada en el keystore
    # para ello necesitamos el alias y la contrasena
    key_data = get_key(alias, password)

    # recuperar la clave privada guardada en formato pem
    private_key_pem = key_data["private_key"]

    # convertir el texto pem en un objeto de clave privada
    # password=None porque la clave se guardo sin cifrado individual
    # la proteccion se aplica al contenido completo del keystore
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("ascii"),
        password=None
    )

    # recuperar el DN original del almacen
    subject_data = key_data["subject"]

    # convertir el texto del DN en un objeto que pueda utilizar x509
    subject = x509.Name.from_rfc4514_string(subject_data)

    # crear la solicitud de firma del certificado
    csr = (
        x509.CertificateSigningRequestBuilder()
        # anadir los datos del titular a la solicitud
        .subject_name(subject)
        # firmar la solicitud con la clave privada y el algoritmo sha256
        .sign(private_key, hashes.SHA256())
    )

    # devolver la solicitud csr generada
    return csr


# ==========================================
# ================ SAVE CSR ================
# ==========================================

def save_csr(csr, filename):
    # definir la carpeta donde se guardaran las solicitudes
    data_dir = "data"

    # crear la carpeta si no existe
    os.makedirs(data_dir, exist_ok=True)

    # eliminar las rutas de carpetas del nombre recibido
    # asi evitamos que se guarde el archivo en otra ubicacion
    filename = os.path.basename(filename)

    # comprobar si el nombre termina en .csr
    # si no tiene la extension, anadirla automaticamente
    if not filename.lower().endswith(".csr"):
        filename += ".csr"

    # crear la ruta completa del archivo dentro de la carpeta data
    filepath = os.path.join(data_dir, filename)

    # convertir la solicitud csr al formato pem
    # pem permite guardar la solicitud en un archivo de texto
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    # abrir el archivo en modo escritura binaria
    # wb permite escribir los datos en formato binario
    with open(filepath, "wb") as file:
        # escribir la solicitud csr en el archivo
        file.write(csr_pem)

    # devolver la ruta donde se ha guardado la solicitud
    return filepath
