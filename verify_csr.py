
# funciones para verificar solicitudes csr
# permite comprobar si una solicitud es valida y mostrar su informacion

# importar os para comprobar si los archivos existen y poder leerlos
import os

# importar x509 para trabajar con solicitudes de certificados
from cryptography import x509

# importar el error que puede producirse al comprobar una firma
from cryptography.exceptions import InvalidSignature


# ==========================================
# ============== VERIFY CSR ================
# ==========================================

def verify_csr(filepath):
    # comprobar que el archivo indicado existe y es un archivo normal
    if not os.path.isfile(filepath):
        raise ValueError("El archivo CSR no existe")

    try:
        # abrir el archivo en modo lectura binaria
        # rb permite leer el contenido sin modificar sus bytes
        with open(filepath, "rb") as file:
            csr_data = file.read()

        # cargar los datos del archivo como una solicitud csr en formato pem
        # si el contenido no tiene el formato esperado, se producira un error
        csr = x509.load_pem_x509_csr(csr_data)

        # comprobar si la firma de la solicitud es valida
        # esto permite verificar que la solicitud no se ha modificado
        if not csr.is_signature_valid:
            raise ValueError("La firma de la CSR no es valida")

        # devolver la solicitud para poder consultar sus datos
        return csr

    # controlar errores relacionados con el formato de la solicitud
    except ValueError as error:
        # si el error indica que la firma no es valida, mantener ese mensaje
        if str(error) == "La firma de la CSR no es valida":
            raise

        # mostrar un error si el archivo no contiene una csr pem valida
        raise ValueError("El archivo no contiene una CSR PEM valida") from error

    # controlar errores al leer el archivo o comprobar la firma
    except (OSError, InvalidSignature) as error:
        raise ValueError("No se ha podido leer o verificar la CSR") from error


# ==========================================
# ============ SHOW CSR INFO ===============
# ==========================================

def show_csr_info(csr):
    # dejar una linea en blanco para separar la informacion anterior
    print()

    # mostrar el titulo de la informacion de la csr
    print("===================================")
    print("          INFORMACION CSR")
    print("===================================")

    # mostrar los datos del titular de la solicitud
    print("Subject:", csr.subject.rfc4514_string())

    # mostrar el algoritmo hash utilizado para generar la firma
    print("Algoritmo:", csr.signature_hash_algorithm.name)

    # indicar si la firma de la solicitud es valida
    print("Firma valida:", csr.is_signature_valid)

    # mostrar el tipo de clave publica incluida en la solicitud
    print("Clave publica:", csr.public_key().__class__.__name__)

    # mostrar la linea final para cerrar la informacion
    print("===================================")
