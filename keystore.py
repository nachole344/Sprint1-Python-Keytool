
# almacen de claves cifrado (simulacion de keystore)

import os
import json
import base64

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization


DATA_DIR = "data"
KEYSTORE_FILE = os.path.join(DATA_DIR, "keystore.enc")
ITERATIONS = 600000

# identificador del formato binario del keystore
MAGIC = b"KS01"
SALT_SIZE = 16


def keystore_exists():
    return os.path.exists(KEYSTORE_FILE)


def create_keystore():
    os.makedirs(DATA_DIR, exist_ok=True)


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


def read_keystore_file():
    # leer el archivo en formato binario
    with open(KEYSTORE_FILE, "rb") as file:
        content = file.read()

    # comprobar si utiliza el nuevo formato binario
    if content.startswith(MAGIC):
        if len(content) <= len(MAGIC) + SALT_SIZE:
            raise ValueError("El KeyStore esta incompleto")

        salt_start = len(MAGIC)
        salt_end = salt_start + SALT_SIZE

        salt = content[salt_start:salt_end]
        encrypted_binary = content[salt_end:]

        # fernet necesita el token en formato Base64 URL-safe
        encrypted_data = base64.urlsafe_b64encode(encrypted_binary)

        return salt, encrypted_data

    # compatibilidad con el formato JSON anterior
    try:
        stored = json.loads(content.decode("utf-8"))

        salt = base64.b64decode(
            stored["salt"],
            validate=True
        )

        encrypted_data = stored["data"].encode("ascii")

        if len(salt) != SALT_SIZE:
            raise ValueError("Salt incorrecto")

        return salt, encrypted_data

    except (ValueError, KeyError, TypeError, UnicodeError) as error:
        raise ValueError(
            "El KeyStore esta danado o tiene un formato incorrecto"
        ) from error


def save_keystore(data, password):
    create_keystore()

    # reutilizar el salt si ya existe un almacen
    if keystore_exists():
        salt, _ = read_keystore_file()
    else:
        salt = os.urandom(SALT_SIZE)

    # cifrar los datos con la clave derivada de la contrasena
    fernet = Fernet(derive_key(password, salt))

    encrypted_data = fernet.encrypt(
        json.dumps(data).encode("utf-8")
    )

    # convertir el token Base64 a bytes binarios
    encrypted_binary = base64.urlsafe_b64decode(encrypted_data)

    # construir el archivo: identificador + salt + datos cifrados
    keystore_binary = MAGIC + salt + encrypted_binary

    # escritura atomica para evitar archivos incompletos
    tmp_file = KEYSTORE_FILE + ".tmp"

    try:
        with open(tmp_file, "wb") as file:
            file.write(keystore_binary)

        os.replace(tmp_file, KEYSTORE_FILE)

    finally:
        if os.path.exists(tmp_file):
            os.remove(tmp_file)

    # restringir los permisos cuando el sistema lo permita
    try:
        os.chmod(KEYSTORE_FILE, 0o600)
    except OSError:
        pass


def load_keystore(password):
    if not keystore_exists():
        raise FileNotFoundError(
            "El KeyStore no existe. Genera primero un par de claves."
        )

    try:
        salt, encrypted_data = read_keystore_file()

        fernet = Fernet(derive_key(password, salt))

        decrypted_data = fernet.decrypt(encrypted_data)

        data = json.loads(decrypted_data.decode("utf-8"))

        if not isinstance(data, dict):
            raise ValueError("El contenido no es un diccionario")

        return data

    except InvalidToken as error:
        raise ValueError(
            "Contrasena incorrecta o KeyStore danado"
        ) from error

    except (ValueError, KeyError, TypeError, UnicodeError) as error:
        raise ValueError(
            "El KeyStore esta danado o tiene un formato incorrecto"
        ) from error

    except OSError as error:
        raise ValueError(
            "No se ha podido leer el KeyStore"
        ) from error


def save_key(alias, private_key, subject, password):
    if not alias or not alias.strip():
        raise ValueError("El alias no puede estar vacio")

    if not password:
        raise ValueError("La contrasena no puede estar vacia")

    # recuperar los datos existentes o crear un almacen nuevo
    data = load_keystore(password) if keystore_exists() else {}

    if alias in data:
        raise ValueError("El alias ya existe")

    # convertir la clave privada a formato PEM
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("ascii")

    # guardar la clave y los datos del titular
    data[alias] = {
        "private_key": private_key_pem,
        "subject": subject.rfc4514_string()
    }

    save_keystore(data, password)


def alias_exists(alias, password):
    return alias in load_keystore(password)


def list_aliases(password):
    return list(load_keystore(password).keys())


def get_key(alias, password):
    data = load_keystore(password)

    if alias not in data:
        raise ValueError("El alias no existe")

    return data[alias]
