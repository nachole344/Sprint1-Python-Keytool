# funciones para leer, 
# mostrar y guardar certificados digitales y listas de revocacion (crl)

# hashlib permite calcular la huella digital sha-256 de un certificado
import hashlib

# x509 contiene las funciones para trabajar con certificados y listas crl
from cryptography import x509

# InvalidSignature se utiliza cuando una firma digital no es correcta
from cryptography.exceptions import InvalidSignature

# serialization permite convertir claves y certificados a diferentes formatos
from cryptography.hazmat.primitives import serialization

# rsa permite identificar si una clave publica utiliza el algoritmo rsa
from cryptography.hazmat.primitives.asymmetric import rsa


# ==========================================
# ============ LEER ARCHIVOS ===============
# ==========================================

def _read_file(filepath, kind):
    # abrir el archivo en modo binario para poder leer tanto texto como binario
    try:
        with open(filepath, "rb") as file:
            # devolver todo el contenido del archivo
            return file.read()

    # controlar el error si el archivo no existe en la ruta indicada
    except FileNotFoundError as error:
        raise ValueError(f"El archivo {kind} no existe: {filepath}") from error

    # controlar otros errores de lectura, como problemas de permisos
    except OSError as error:
        raise ValueError(f"No se ha podido leer el archivo {kind}: {filepath}") from error


def load_certificate_file(filepath):
    # leer el contenido del archivo del certificado
    content = _read_file(filepath, "del certificado")

    # primero intentar cargar el certificado en formato pem
    # pem es un formato de texto que contiene los datos codificados en base64
    try:
        return x509.load_pem_x509_certificate(content)
    except ValueError:
        # si no es pem, continuar e intentar leerlo como der
        pass

    # intentar cargar el certificado en formato der
    # der es un formato binario que almacena los datos del certificado
    try:
        return x509.load_der_x509_certificate(content)
    except ValueError as error:
        # si fallan los dos formatos, el archivo no contiene un certificado valido
        raise ValueError("El archivo no contiene un certificado válido (PEM o DER)") from error


def load_certificate_pem(pem_text):
    # recibir el certificado como texto en formato pem
    # convertir el texto a bytes porque la libreria necesita datos binarios
    # despues cargarlo y devolver el objeto certificado
    return x509.load_pem_x509_certificate(pem_text.encode("ascii"))


def load_crl_file(filepath):
    # leer el contenido del archivo que contiene la lista de revocacion
    content = _read_file(filepath, "de la CRL")

    # intentar cargar la crl en formato pem
    # una crl contiene informacion sobre certificados que han sido revocados
    try:
        return x509.load_pem_x509_crl(content)
    except ValueError:
        # si no es pem, probar el formato der
        pass

    # intentar cargar la crl en formato der
    try:
        return x509.load_der_x509_crl(content)
    except ValueError as error:
        # mostrar un error si el contenido no es una crl valida
        raise ValueError("El archivo no contiene una CRL válida (PEM o DER)") from error


def write_certificate(certificate, filepath, rfc=False):
    # elegir el formato en el que se guardara el certificado
    # por defecto se utiliza der, que es binario
    # si rfc es true, se utiliza pem, que es texto
    encoding = serialization.Encoding.PEM if rfc else serialization.Encoding.DER

    # abrir el archivo en modo escritura binaria
    # si el archivo ya existe, se sustituye su contenido
    with open(filepath, "wb") as file:
        # convertir el certificado al formato elegido y escribirlo
        file.write(certificate.public_bytes(encoding))


# ==========================================
# ============== COMPROBACIONES ============
# ==========================================

def fingerprint_sha256(certificate):
    # convertir el certificado a der para tener una representacion binaria
    # calcular su huella digital utilizando el algoritmo sha-256
    # hexdigest devuelve el resultado en hexadecimal
    # upper convierte las letras a mayusculas
    digest = hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest().upper()

    # separar el resultado en grupos de dos caracteres
    # unir los grupos con dos puntos para facilitar su lectura
    # la huella sirve para identificar el certificado y detectar cambios
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def is_signed_by(certificate, issuer):
    # comprobar si la firma del certificado es valida utilizando
    # el certificado del emisor y su clave publica
    try:
        certificate.verify_directly_issued_by(issuer)

        # si no se produce ningun error, la comprobacion ha funcionado
        return True

    # controlar los errores que pueden aparecer durante la verificacion
    # valueerror: los datos o la firma no son validos
    # typeerror: hay un tipo de dato incompatible
    # invalidsignature: la firma no coincide con la clave utilizada
    except (ValueError, TypeError, InvalidSignature):
        return False


def is_self_signed(certificate):
    # un certificado autofirmado utiliza el mismo certificado
    # como certificado que se comprueba y como supuesto emisor
    # se comprueba su firma con su propia clave publica
    return is_signed_by(certificate, certificate)


def same_public_key(certificate, public_key_pem):
    # cargar la clave publica guardada en formato pem
    stored = serialization.load_pem_public_key(public_key_pem.encode("ascii"))

    # funcion interna para convertir una clave publica a formato der
    # se utiliza el formato subjectpublickeyinfo para representar la clave
    def to_der(key):
        return key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

    # comparar las dos claves en el mismo formato binario
    # si son iguales, pertenecen a la misma clave publica
    return to_der(certificate.public_key()) == to_der(stored)


def key_description(public_key):
    # comprobar si la clave publica utiliza el algoritmo rsa
    if isinstance(public_key, rsa.RSAPublicKey):
        # indicar el algoritmo y el tamaño de la clave en bits
        return f"RSA {public_key.key_size} bits"

    # si utiliza otro algoritmo, devolver el nombre de su tipo
    return type(public_key).__name__


# ==========================================
# ============== MOSTRAR ===================
# ==========================================

def show_certificate_info(certificate, indent=""):
    # obtener el algoritmo hash utilizado para firmar el certificado
    hash_algorithm = certificate.signature_hash_algorithm

    # obtener su nombre o indicar que no se ha podido identificar
    algorithm = hash_algorithm.name if hash_algorithm else "desconocido"

    # mostrar el titular del certificado
    # rfc4514_string convierte el nombre a una cadena legible
    print(f"{indent}Titular: {certificate.subject.rfc4514_string()}")

    # mostrar la entidad que ha emitido el certificado
    print(f"{indent}Emisor: {certificate.issuer.rfc4514_string()}")

    # mostrar el numero de serie en hexadecimal
    print(f"{indent}Número de serie: {certificate.serial_number:x}")

    # mostrar las fechas de inicio y final de validez en horario utc
    print(f"{indent}Válido desde: {certificate.not_valid_before_utc:%Y-%m-%d %H:%M} UTC"
          f" hasta: {certificate.not_valid_after_utc:%Y-%m-%d %H:%M} UTC")

    # mostrar el algoritmo hash utilizado en la firma y el tipo de clave
    print(f"{indent}Algoritmo de firma: {algorithm} con RSA")

    # mostrar el tipo de clave publica y su tamaño
    print(f"{indent}Clave pública: {key_description(certificate.public_key())}")

    # mostrar la huella digital sha-256 del certificado
    print(f"{indent}Huella SHA-256: {fingerprint_sha256(certificate)}")

    # comprobar si el certificado esta firmado con su propia clave publica
    if is_self_signed(certificate):
        print(f"{indent}Autofirmado: sí (firma comprobada con su propia clave pública)")
    else:
        # si no es autofirmado, esta comprobacion no confirma quien lo ha emitido
        print(f"{indent}Autofirmado: no (hace falta el certificado del emisor para comprobar su firma)")


def show_crl_info(crl):
    # mostrar la entidad que ha emitido la lista de revocacion
    print(f"Emisor: {crl.issuer.rfc4514_string()}")

    # mostrar la fecha de la ultima actualizacion de la crl
    print(f"Última actualización: {crl.last_update_utc:%Y-%m-%d %H:%M} UTC")

    # comprobar si la crl indica una fecha para su proxima actualizacion
    if crl.next_update_utc:
        # mostrar cuando deberia actualizarse la lista
        print(f"Próxima actualización: {crl.next_update_utc:%Y-%m-%d %H:%M} UTC")

    # convertir los certificados revocados en una lista
    # cada elemento contiene informacion de un certificado revocado
    revoked = list(crl)

    # mostrar cuantos certificados aparecen en la lista
    print(f"Certificados revocados: {len(revoked)}")

    # recorrer todos los certificados revocados para mostrar sus datos
    for item in revoked:
        # mostrar el numero de serie y la fecha de revocacion
        # el numero de serie se representa en hexadecimal
        print(f"  - serie {item.serial_number:x}, revocado el {item.revocation_date_utc:%Y-%m-%d %H:%M} UTC")

    # avisar de que solo se ha leido la crl y mostrado su contenido
    # no se ha comprobado si su firma pertenece realmente al emisor
    print("Nota: no se ha comprobado la firma de la CRL (no se dispone del certificado del emisor).")