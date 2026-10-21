
# almacen de claves cifrado (simulacion de keystore)
# el archivo data/keystore.enc contiene un diccionario {alias: entrada} cifrado con la contraseña del almacen

import os
import json
import base64
import datetime

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization

from crypto_utils import private_key_to_pem


# carpeta data junto a los archivos del programa (no depende de desde donde se ejecute)
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
KEYSTORE_FILE = os.path.join(DATA_DIR, "keystore.enc")
ITERATIONS = 600000

# identificador del formato binario del keystore
MAGIC = b"KS01"
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

    os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
    return filename


def input_path(filename):
    # ruta de un archivo de entrada: si no existe tal cual y no lleva carpeta,
    # se busca tambien en data/ (donde se guardan los archivos generados)
    if not os.path.exists(filename) and not os.path.dirname(filename):
        in_data = os.path.join(DATA_DIR, filename)
        if os.path.exists(in_data):
            return in_data

    return filename


# ==========================================
# ============ ARCHIVO CIFRADO =============
# ==========================================

def keystore_exists(path=None):
    return os.path.isfile(_path(path))


def create_keystore(path=None):
    # crear la carpeta donde se guardara el almacen
    os.makedirs(os.path.dirname(os.path.abspath(_path(path))), exist_ok=True)


def derive_key(password, salt):
    # derivar una clave de cifrado a partir de la contrasena
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS
    )

    key = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


def read_keystore_file(path=None):
    # leer el archivo en formato binario
    with open(_path(path), "rb") as file:
        content = file.read()

    # comprobar que el archivo empieza por el identificador del formato
    # y que contiene algo mas que la cabecera
    if not content.startswith(MAGIC) or len(content) <= len(MAGIC) + SALT_SIZE:
        raise ValueError("El KeyStore está dañado o tiene un formato incorrecto")

    salt_start = len(MAGIC)
    salt_end = salt_start + SALT_SIZE

    salt = content[salt_start:salt_end]
    encrypted_binary = content[salt_end:]

    # fernet necesita el token en formato Base64 URL-safe
    encrypted_data = base64.urlsafe_b64encode(encrypted_binary)

    return salt, encrypted_data


def save_keystore(data, password, path=None):
    create_keystore(path)
    file_path = _path(path)

    # salt nuevo en cada guardado (asi tambien cambia al cambiar la contraseña)
    salt = os.urandom(SALT_SIZE)

    # cifrar los datos con la clave derivada de la contrasena
    # fernet usa AES + HMAC: cifra y ademas detecta si los datos se han modificado
    fernet = Fernet(derive_key(password, salt))

    encrypted_data = fernet.encrypt(
        json.dumps(data).encode("utf-8")
    )

    # convertir el token Base64 a bytes binarios
    encrypted_binary = base64.urlsafe_b64decode(encrypted_data)

    # construir el archivo: identificador + salt + datos cifrados
    keystore_binary = MAGIC + salt + encrypted_binary

    # escritura atomica para evitar archivos incompletos
    tmp_file = file_path + ".tmp"

    try:
        with open(tmp_file, "wb") as file:
            file.write(keystore_binary)

        os.replace(tmp_file, file_path)

    finally:
        if os.path.exists(tmp_file):
            os.remove(tmp_file)

    # restringir los permisos cuando el sistema lo permita
    try:
        os.chmod(file_path, 0o600)
    except OSError:
        pass


def load_keystore(password, path=None):
    if not keystore_exists(path):
        raise FileNotFoundError(
            "El KeyStore no existe. Genera primero un par de claves."
        )

    try:
        salt, encrypted_data = read_keystore_file(path)

        fernet = Fernet(derive_key(password, salt))

        decrypted_data = fernet.decrypt(encrypted_data)

        data = json.loads(decrypted_data.decode("utf-8"))

        if not isinstance(data, dict):
            raise ValueError("El contenido no es un diccionario")

        return data

    except InvalidToken as error:
        raise ValueError(
            "Contraseña del KeyStore incorrecta o KeyStore dañado"
        ) from error

    except (ValueError, KeyError, TypeError, UnicodeError) as error:
        raise ValueError(
            "El KeyStore está dañado o tiene un formato incorrecto"
        ) from error

    except OSError as error:
        raise ValueError(
            "No se ha podido leer el KeyStore"
        ) from error


# ==========================================
# ============== ENTRADAS ==================
# ==========================================

def now_text():
    # fecha de creacion de una entrada (hora UTC)
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def entry_type(entry):
    # las entradas antiguas no tenian tipo: eran claves privadas
    return entry.get("type", PRIVATE_KEY_ENTRY)


def certificate_to_pem(certificate):
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


def check_alias(alias):
    if not alias or not alias.strip():
        raise ValueError("El alias no puede estar vacío")


def add_entry(alias, entry, password, path=None):
    # añadir una entrada nueva al almacen (si no existe, el almacen se crea)
    check_alias(alias)

    if not password:
        raise ValueError("La contraseña no puede estar vacía")

    # recuperar los datos existentes o crear un almacen nuevo
    data = load_keystore(password, path) if keystore_exists(path) else {}

    if alias in data:
        raise ValueError("El alias ya existe")

    data[alias] = entry
    save_keystore(data, password, path)


def replace_entry(alias, entry, password, path=None):
    # sustituir una entrada que ya existe (por ejemplo, al cambiar su contraseña)
    data = load_keystore(password, path)

    if alias not in data:
        raise ValueError("El alias no existe")

    data[alias] = entry
    save_keystore(data, password, path)


def delete_entry(alias, password, path=None):
    data = load_keystore(password, path)

    if alias not in data:
        raise ValueError("El alias no existe")

    del data[alias]
    save_keystore(data, password, path)


def rename_entry(alias, new_alias, password, path=None):
    check_alias(new_alias)
    data = load_keystore(password, path)

    if alias not in data:
        raise ValueError("El alias no existe")

    if new_alias in data:
        raise ValueError("El alias de destino ya existe")

    # se recrea el diccionario para conservar el orden de las entradas
    data = {(new_alias if key == alias else key): value for key, value in data.items()}
    save_keystore(data, password, path)


def change_store_password(password, new_password, path=None):
    # descifrar con la contraseña antigua y volver a cifrar con la nueva
    data = load_keystore(password, path)
    save_keystore(data, new_password, path)


def save_key(alias, private_key, subject, password, key_password=None,
             certificate=None, path=None):
    # si no se indica una contraseña para el alias, se usa la del keystore
    # (igual que hace keytool cuando se pulsa ENTER)
    if not key_password:
        key_password = password

    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")

    # guardar la clave (cifrada con la contraseña del alias) y los datos del titular
    entry = {
        "type": PRIVATE_KEY_ENTRY,
        "private_key": private_key_to_pem(private_key, key_password),
        "public_key": public_key_pem,
        "key_size": private_key.key_size,
        "subject": subject.rfc4514_string(),
        "certificate": certificate_to_pem(certificate) if certificate else None,
        "created": now_text(),
    }

    add_entry(alias, entry, password, path)


def alias_exists(alias, password, path=None):
    return alias in load_keystore(password, path)


def list_aliases(password, path=None):
    return list(load_keystore(password, path).keys())


def get_key(alias, password, path=None):
    data = load_keystore(password, path)

    if alias not in data:
        raise ValueError("El alias no existe")

    return data[alias]
