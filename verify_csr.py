# funciones para verificar solicitudes csr y mostrar su informacion
# tambien se puede usar desde la terminal: python verify_csr.py archivo.csr

import os
import sys

# modulo para leer y trabajar con solicitudes de certificados x.509
from cryptography import x509

# clase para identificar claves publicas del tipo rsa
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def verify_csr(filepath):
    # comprobar que la ruta corresponde a un archivo existente
    if not os.path.isfile(filepath):
        raise ValueError("El archivo CSR no existe")

    try:
        # abrir el archivo en modo binario y leer todo su contenido
        with open(filepath, "rb") as file:
            csr_data = file.read()
    except OSError as error:
        # controlar errores de lectura, como falta de permisos o problemas con la ruta
        raise ValueError("No se ha podido leer la CSR") from error

    try:
        # interpretar los datos como una solicitud csr en formato pem
        csr = x509.load_pem_x509_csr(csr_data)
    except ValueError as error:
        # informar si el archivo no tiene el formato esperado o no se puede interpretar
        raise ValueError("El archivo no contiene una CSR PEM valida") from error

    # is_signature_valid es una propiedad: devuelve True/False, no lanza excepcion
    # comprueba que la csr esta firmada con la clave privada que corresponde a su clave publica
    if not csr.is_signature_valid:
        # rechazar la solicitud si su firma no se puede validar
        raise ValueError("La firma de la CSR no es valida")

    # devolver el objeto csr para que otras funciones puedan consultar sus datos
    return csr


def show_csr_info(csr):
    # obtener la clave publica incluida en la solicitud
    public_key = csr.public_key()

    # comprobar si la clave publica es rsa para mostrar tambien su tamaño
    if isinstance(public_key, rsa.RSAPublicKey):
        key_info = f"RSA {public_key.key_size} bits"
    else:
        # si es otro tipo de clave, mostrar el nombre de su clase
        key_info = type(public_key).__name__

    # mostrar un encabezado para separar la informacion de la terminal
    print()
    print("===================================")
    print("          INFORMACION CSR")
    print("===================================")

    # mostrar los datos del titular de la solicitud
    print("Subject:", csr.subject.rfc4514_string())
    country = csr.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
    print("Country:", country[0].value if country else "Unknown")
    hash_algorithm = csr.signature_hash_algorithm

    # mostrar el nombre del algoritmo o un texto alternativo si no se conoce
    print("Algoritmo:", hash_algorithm.name if hash_algorithm else "desconocido")

    # mostrar el resultado de la comprobacion de la firma
    print("Firma valida:", csr.is_signature_valid)

    # mostrar el tipo de clave publica y, si es rsa, su tamaño
    print("Clave publica:", key_info)

    # cerrar el bloque de informacion
    print("===================================")


def main(argv=None):
    # uso desde la terminal: python verify_csr.py archivo.csr

    # utilizar los argumentos recibidos o los escritos en la terminal
    argv = sys.argv[1:] if argv is None else argv

    # comprobar que se ha indicado exactamente un archivo
    # si se solicita ayuda, mostrar las instrucciones de uso
    if len(argv) != 1 or argv[0] in ("-h", "--help", "-?"):
        print("Uso: python verify_csr.py ARCHIVO.csr")
        print("Comprueba que el archivo es una CSR (PEM) con firma valida y muestra su informacion.")

        # devolver 0 si se ha pedido ayuda y 1 si faltan o sobran argumentos
        return 0 if argv and argv[0] in ("-h", "--help", "-?") else 1

    try:
        # verificar la solicitud y recuperar sus datos
        csr = verify_csr(argv[0])
    except ValueError as error:
        # mostrar el motivo del error y terminar con codigo de fallo
        print(f"Error: {error}")
        return 1

    # informar de que la csr ha superado las comprobaciones
    print("CSR valida correctamente.")

    # mostrar los datos principales de la solicitud
    show_csr_info(csr)

    # devolver 0 para indicar que el proceso ha terminado correctamente
    return 0


# ejecutar main solo cuando el archivo se inicia directamente
# permite importar estas funciones desde otros modulos sin ejecutar el programa
if __name__ == "__main__":
    # finalizar el programa con el codigo devuelto por main
    sys.exit(main())
