
# funciones para generar y guardar solicitudes csr
# una csr es una solicitud de firma de certificado digital


# importar las funciones necesarias para crear solicitudes y certificados
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

# importar las funciones para recuperar una clave del keystore
from keystore import get_key, entry_type, output_path, PRIVATE_KEY_ENTRY
from crypto_utils import load_private_key


# ==========================================
# ============== GENERATE CSR ==============
# ==========================================

def generate_csr_for_alias(alias, password, key_password=None, path=None):
    # recuperar la informacion de la clave guardada en el keystore
    # para ello necesitamos el alias y la contrasena
    key_data = get_key(alias, password, path)

    # una csr solo se puede crear si hay clave privada
    if entry_type(key_data) != PRIVATE_KEY_ENTRY:
        raise ValueError("El alias no tiene clave privada (no es un par de claves)")

    # si no se indica contraseña del alias, se usa la del keystore
    if not key_password:
        key_password = password

    # recuperar la clave privada (esto falla si la contraseña del alias es incorrecta)
    private_key = load_private_key(key_data["private_key"], key_password)

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
    # un nombre sin carpeta se guarda en data/; si lleva carpeta se respeta
    filepath = output_path(filename)

    # convertir la solicitud csr al formato pem
    # pem permite guardar la solicitud en un archivo de texto
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    # abrir el archivo en modo escritura binaria
    with open(filepath, "wb") as file:
        # escribir la solicitud csr en el archivo
        file.write(csr_pem)

    # devolver la ruta donde se ha guardado la solicitud
    return filepath
