```python
# almacen de claves cifrado (simulacion de keystore)
# el archivo data/keystore.enc contiene un diccionario {alias: entrada} cifrado con la contraseña del almacen

import os
import json
import base64
import datetime

# herramientas para cifrar y descifrar los datos del almacen
from cryptography.fernet import Fernet, InvalidToken

# algoritmo hash utilizado para derivar la clave de cifrado
from cryptography.hazmat.primitives import hashes

# funcion para obtener una clave segura a partir de una contraseña
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# herramientas para guardar claves y certificados en formato PEM
from cryptography.hazmat.primitives import serialization

# funcion del proyecto que convierte una clave privada a formato PEM
from crypto_utils import private_key_to_pem


# carpeta data junto a los archivos del programa (no depende de desde donde se ejecute)
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

# ruta por defecto del archivo cifrado
KEYSTORE_FILE = os.path.join(DATA_DIR, "keystore.enc")

# numero de iteraciones utilizadas para derivar la clave desde la contraseña
# un valor alto hace que probar contraseñas sea mas lento
ITERATIONS = 600000

# identificador del formato binario del keystore
MAGIC = b"KS01"

# tamaño del salt en bytes
# el salt es un valor aleatorio que ayuda a obtener claves diferentes
SALT_SIZE = 16

# tipos de entrada que puede guardar el almacen (nombres como en keytool)
PRIVATE_KEY_ENTRY = "PrivateKeyEntry"
TRUSTED_CERT_ENTRY = "trustedCertEntry"
SECRET_KEY_ENTRY = "SecretKeyEntry"


# ==========================================
# ================ RUTAS ===================
# ==========================================

def _path(path):
    # si no se indica ruta (opcion -keystore) se usa data/keystore.enc
    return path or KEYSTORE_FILE


def output_path(filename):
    # ruta donde se escribe un archivo de salida (csr, certificado...)
    # un nombre sin carpeta se guarda en data/; si lleva carpeta se respeta
    if not os.path.dirname(filename):
        filename = os.path.join(DATA_DIR, filename)

    # crear la carpeta de destino si todavia no existe
    os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
    return filename


def input_path(filename):
    # ruta de un archivo de entrada: si no existe tal cual y no lleva carpeta,
    # se busca tambien en data/ (donde se guardan los archivos generados)
    if not os.path.exists(filename) and not os.path.dirname(filename):
        in_data = os.path.join(DATA_DIR, filename)

        # utilizar la ruta de data si el archivo se encuentra alli
        if os.path.exists(in_data):
            return in_data

    # devolver la ruta original si no se encuentra en data/
    return filename


# ==========================================
# ============ ARCHIVO CIFRADO =============
# ==========================================

def keystore_exists(path=None):
    # comprobar si existe el archivo del almacen
    return os.path.isfile(_path(path))


def create_keystore(path=None):
    # crear la carpeta donde se guardara el almacen
    # no crea el archivo cifrado, solo prepara su directorio
    os.makedirs(os.path.dirname(os.path.abspath(_path(path))), exist_ok=True)


def derive_key(password, salt):
    # derivar una clave de cifrado a partir de la contraseña y el salt
    # PBKDF2 aplica SHA-256 muchas veces para dificultar los ataques por fuerza bruta
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # longitud de la clave en bytes
        salt=salt,
        iterations=ITERATIONS
    )

    # convertir la contraseña a bytes y obtener la clave derivada
    key = kdf.derive(password.encode("utf-8"))

    # fernet necesita que la clave este codificada en Base64 URL-safe
    return base64.urlsafe_b64encode(key)


def read_keystore_file(path=None):
    # abrir el archivo en modo binario para leer sus bytes
    with open(_path(path), "rb") as file:
        content = file.read()

    # comprobar que el archivo empieza por el identificador del formato
    # y que contiene algo mas que la cabecera
    if not content.startswith(MAGIC) or len(content) <= len(MAGIC) + SALT_SIZE:
        raise ValueError("El KeyStore está dañado o tiene un formato incorrecto")

    # calcular donde empieza y termina el salt
    salt_start = len(MAGIC)
    salt_end = salt_start + SALT_SIZE

    # separar el salt de los datos cifrados
    salt = content[salt_start:salt_end]
    encrypted_binary = content[salt_end:]

    # fernet necesita el token en formato Base64 URL-safe
    encrypted_data = base64.urlsafe_b64encode(encrypted_binary)

    # devolver el salt y los datos cifrados para poder descifrarlos
    return salt, encrypted_data


def save_keystore(data, password, path=None):
    # preparar la carpeta donde se guardara el almacen
    create_keystore(path)
    file_path = _path(path)

    # generar un salt nuevo en cada guardado
    # asi se obtiene una clave derivada diferente aunque se use la misma contraseña
    salt = os.urandom(SALT_SIZE)

    # derivar la clave y preparar el sistema de cifrado
    # fernet cifra los datos y tambien comprueba si han sido modificados
    fernet = Fernet(derive_key(password, salt))

    # convertir el diccionario a JSON, pasarlo a bytes y cifrarlo
    encrypted_data = fernet.encrypt(
        json.dumps(data).encode("utf-8")
    )

    # convertir el token Base64 a bytes binarios
    encrypted_binary = base64.urlsafe_b64decode(encrypted_data)

    # construir el archivo: identificador + salt + datos cifrados
    keystore_binary = MAGIC + salt + encrypted_binary

    # escribir primero en un archivo temporal para evitar dejar el almacen incompleto
    tmp_file = file_path + ".tmp"

    try:
        # guardar todo el contenido cifrado en el archivo temporal
        with open(tmp_file, "wb") as file:
            file.write(keystore_binary)

        # sustituir el archivo anterior por el nuevo
        # os.replace realiza el cambio en una sola operacion
        os.replace(tmp_file, file_path)

    finally:
        # eliminar el temporal si sigue existiendo despues de la escritura
        if os.path.exists(tmp_file):
            os.remove(tmp_file)

    # restringir los permisos cuando el sistema lo permita
    # 0o600 permite leer y escribir al propietario en sistemas compatibles
    try:
        os.chmod(file_path, 0o600)
    except OSError:
        # si el sistema no admite este cambio, continuar igualmente
        pass


def load_keystore(password, path=None):
    # comprobar que existe el archivo antes de intentar abrirlo
    if not keystore_exists(path):
        raise FileNotFoundError(
            "El KeyStore no existe. Genera primero un par de claves."
        )

    try:
        # leer el salt y los datos cifrados del archivo
        salt, encrypted_data = read_keystore_file(path)

        # obtener la misma clave usando la contraseña y el salt guardados
        fernet = Fernet(derive_key(password, salt))

        # descifrar el contenido; si la contraseña no es correcta, fallara
        decrypted_data = fernet.decrypt(encrypted_data)

        # convertir los bytes descifrados a texto y recuperar el diccionario JSON
        data = json.loads(decrypted_data.decode("utf-8"))

        # comprobar que el contenido recuperado tiene el formato esperado
        if not isinstance(data, dict):
            raise ValueError("El contenido no es un diccionario")

        return data

    except InvalidToken as error:
        # puede significar que la contraseña es incorrecta o que el contenido
        # cifrado ha sido modificado o esta dañado
        raise ValueError(
            "Contraseña del KeyStore incorrecta o KeyStore dañado"
        ) from error

    except (ValueError, KeyError, TypeError, UnicodeError) as error:
        # informar de errores en el formato o en los datos descifrados
        raise ValueError(
            "El KeyStore está dañado o tiene un formato incorrecto"
        ) from error

    except OSError as error:
        # controlar errores al acceder al archivo, por ejemplo, falta de permisos
        raise ValueError(
            "No se ha podido leer el KeyStore"
        ) from error


# ==========================================
# ============== ENTRADAS ==================
# ==========================================

def now_text():
    # obtener la fecha y hora actual en UTC
    # el formato ISO facilita guardar y consultar la fecha
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def entry_type(entry):
    # devolver el tipo de entrada guardado en el diccionario
    # las entradas antiguas no tenian tipo: se consideran claves privadas
    return entry.get("type", PRIVATE_KEY_ENTRY)


def certificate_to_pem(certificate):
    # convertir un certificado al formato PEM y devolverlo como texto
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


def check_alias(alias):
    # comprobar que el alias no sea nulo ni contenga solo espacios
    if not alias or not alias.strip():
        raise ValueError("El alias no puede estar vacío")


def add_entry(alias, entry, password, path=None):
    # añadir una entrada nueva al almacen (si no existe, el almacen se crea)
    check_alias(alias)

    # no permitir una contraseña vacia para el almacen
    if not password:
        raise ValueError("La contraseña no puede estar vacía")

    # recuperar las entradas existentes o empezar con un diccionario vacio
    data = load_keystore(password, path) if keystore_exists(path) else {}

    # impedir que dos entradas tengan el mismo alias
    if alias in data:
        raise ValueError("El alias ya existe")

    # guardar la entrada usando el alias como clave del diccionario
    data[alias] = entry

    # volver a cifrar y guardar todo el almacen
    save_keystore(data, password, path)


def replace_entry(alias, entry, password, path=None):
    # cargar el almacen con su contraseña
    data = load_keystore(password, path)

    # comprobar que la entrada que se quiere sustituir existe
    if alias not in data:
        raise ValueError("El alias no existe")

    # reemplazar la entrada anterior por la nueva
    data[alias] = entry

    # guardar de nuevo el almacen cifrado
    save_keystore(data, password, path)


def delete_entry(alias, password, path=None):
    # cargar las entradas del almacen
    data = load_keystore(password, path)

    # comprobar que el alias existe antes de eliminarlo
    if alias not in data:
        raise ValueError("El alias no existe")

    # eliminar la entrada del diccionario
    del data[alias]

    # guardar el almacen sin la entrada eliminada
    save_keystore(data, password, path)


def rename_entry(alias, new_alias, password, path=None):
    # comprobar que el nuevo alias sea valido
    check_alias(new_alias)

    # cargar las entradas del almacen
    data = load_keystore(password, path)

    # comprobar que el alias original existe
    if alias not in data:
        raise ValueError("El alias no existe")

    # evitar que el nuevo alias ya pertenezca a otra entrada
    if new_alias in data:
        raise ValueError("El alias de destino ya existe")

    # recrear el diccionario cambiando solo el alias indicado
    # asi se conserva el orden de las entradas
    data = {(new_alias if key == alias else key): value for key, value in data.items()}

    # guardar el almacen con el alias actualizado
    save_keystore(data, password, path)


def change_store_password(password, new_password, path=None):
    # descifrar el almacen con la contraseña antigua
    data = load_keystore(password, path)

    # guardar los mismos datos cifrandolos con la contraseña nueva
    save_keystore(data, new_password, path)


def save_key(alias, private_key, subject, password, key_password=None,
             certificate=None, path=None):
    # si no se indica una contraseña para el alias, se usa la del keystore
    # (igual que hace keytool cuando se pulsa ENTER)
    if not key_password:
        key_password = password

    # obtener la clave publica correspondiente a la clave privada
    # guardarla en formato PEM para poder recuperarla despues
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")

    # preparar el diccionario con toda la informacion de la entrada
    entry = {
        "type": PRIVATE_KEY_ENTRY,

        # guardar la clave privada protegida con la contraseña del alias
        "private_key": private_key_to_pem(private_key, key_password),

        # guardar la clave publica, que no necesita cifrado
        "public_key": public_key_pem,

        # guardar el tamaño de la clave en bits
        "key_size": private_key.key_size,

        # guardar los datos del titular en formato de nombre X.509
        "subject": subject.rfc4514_string(),

        # guardar el certificado en PEM si se ha proporcionado
        "certificate": certificate_to_pem(certificate) if certificate else None,

        # guardar la fecha de creacion de la entrada
        "created": now_text(),
    }

    # añadir la entrada al almacen y guardar los cambios
    add_entry(alias, entry, password, path)


def alias_exists(alias, password, path=None):
    # comprobar si existe un alias dentro del almacen
    return alias in load_keystore(password, path)


def list_aliases(password, path=None):
    # devolver una lista con todos los alias guardados
    return list(load_keystore(password, path).keys())


def get_key(alias, password, path=None):
    # cargar todas las entradas del almacen
    data = load_keystore(password, path)

    # comprobar que el alias solicitado existe
    if alias not in data:
        raise ValueError("El alias no existe")

    # devolver los datos de la entrada solicitada
    return data[alias]
```