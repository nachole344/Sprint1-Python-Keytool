
# Gestion del almacen cifrado y de las claves

import os
import json
import base64

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization


# ==========================================
# ============== CONFIGURACION =============
# ==========================================

DATA_DIR = "data"
KEYSTORE_FILE = os.path.join(DATA_DIR, "keystore.enc")
ITERATIONS = 600000


# ==========================================
# ============== CREATE ====================
# ==========================================

def create_keystore():
    # Creamos la carpeta de datos si no existe
    os.makedirs(DATA_DIR, exist_ok=True)


# ==========================================
# ============== DERIVE KEY ================
# ==========================================

def derive_key(password, salt):
    # Derivamos una clave a partir de la contrasena
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS
    )

    key = kdf.derive(password.encode("utf-8"))

    # Fernet necesita la clave codificada en Base64 URL-safe
    return base64.urlsafe_b64encode(key)


# ==========================================
# ============== SAVE STORE =================
# ==========================================

def save_keystore(data, password):
    create_keystore()

    # Si ya existe el almacen, conservamos su salt.
    # Asi podemos guardar nuevas claves sin perder las anteriores.
    if os.path.exists(KEYSTORE_FILE):
        with open(KEYSTORE_FILE, "r", encoding="utf-8") as file:
            stored = json.load(file)

        salt = base64.b64decode(stored["salt"], validate=True)
    else:
        salt = os.urandom(16)

    key = derive_key(password, salt)
    fernet = Fernet(key)

    json_data = json.dumps(data).encode("utf-8")
    encrypted_data = fernet.encrypt(json_data)

    keystore_data = {
        "salt": base64.b64encode(salt).decode("ascii"),
        "data": encrypted_data.decode("ascii")
    }

    with open(KEYSTORE_FILE, "w", encoding="utf-8") as file:
        json.dump(keystore_data, file, indent=4)


# ==========================================
# ============== LOAD STORE =================
# ==========================================

def load_keystore(password):
    # No creamos un almacen automaticamente al leerlo
    if not os.path.exists(KEYSTORE_FILE):
        raise FileNotFoundError(
            "El KeyStore no existe. Genera primero un par de claves."
        )

    try:
        with open(KEYSTORE_FILE, "r", encoding="utf-8") as file:
            stored = json.load(file)

        salt = base64.b64decode(stored["salt"], validate=True)
        encrypted_data = stored["data"]

        if len(salt) != 16 or not isinstance(encrypted_data, str):
            raise ValueError("Estructura incorrecta")

        key = derive_key(password, salt)
        fernet = Fernet(key)

        decrypted_data = fernet.decrypt(encrypted_data.encode("ascii"))
        data = json.loads(decrypted_data.decode("utf-8"))

        if not isinstance(data, dict):
            raise ValueError("El contenido no es un diccionario")

        return data

    except InvalidToken:
        raise ValueError("Contrasena incorrecta o KeyStore danado")

    except (json.JSONDecodeError, KeyError, TypeError,
            UnicodeDecodeError, base64.binascii.Error):
        raise ValueError("El KeyStore esta danado o tiene un formato incorrecto")

    except (OSError, UnicodeError):
        raise ValueError("No se ha podido leer el KeyStore")


# ==========================================
# ============== SAVE KEY ==================
# ==========================================

def save_key(alias, private_key, subject, password):
    if not alias or not alias.strip():
        raise ValueError("El alias no puede estar vacio")

    if not password:
        raise ValueError("La contrasena no puede estar vacia")

    # Si no existe el almacen, empezamos uno nuevo.
    if os.path.exists(KEYSTORE_FILE):
        data = load_keystore(password)
    else:
        data = {}

    if alias in data:
        raise ValueError("El alias ya existe")

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("ascii")

    data[alias] = {
        "private_key": private_key_pem,
        "subject": subject.rfc4514_string()
    }

    save_keystore(data, password)


# ==========================================
# ============== ALIAS EXISTS ==============
# ==========================================

def alias_exists(alias, password):
    data = load_keystore(password)
    return alias in data


# ==========================================
# ============== LIST ALIASES ===============
# ==========================================

def list_aliases(password):
    data = load_keystore(password)
    return list(data.keys())


# ==========================================
# ============== GET KEY ===================
# ==========================================

def get_key(alias, password):
    data = load_keystore(password)

    if alias not in data:
        raise ValueError("El alias no existe")

    return data[alias]