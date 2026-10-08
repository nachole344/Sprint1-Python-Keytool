# Para trabajar con archivos, carpetas y JSON
# Tambien para cifrar y convertir datos
import os
import json
import base64

# Libreria cryptography
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
# ================ CREATE ==================
# ==========================================

def create_keystore():
    # Creamos la carpeta data si no existe
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)


# ==========================================
# ================ DERIVE =================
# ==========================================

def derive_key(password, salt):
    # Creamos PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS
    )

    # Generamos la clave
    key = kdf.derive(password.encode())

    # Convertimos la clave al formato Fernet
    return base64.urlsafe_b64encode(key)


# ==========================================
# ============== SAVE KEYSTORE =============
# ==========================================

def save_keystore(data, password):

    create_keystore()

    # Generamos un salt aleatorio
    salt = os.urandom(16)

    # Generamos la clave de cifrado
    key = derive_key(password, salt)

    # Creamos Fernet
    fernet = Fernet(key)

    # Convertimos los datos a JSON
    json_data = json.dumps(data)

    # Ciframos los datos
    encrypted_data = fernet.encrypt(json_data.encode())

    # Guardamos salt y datos cifrados
    keystore_data = {
        "salt": base64.b64encode(salt).decode(),
        "data": encrypted_data.decode()
    }

    # Guardamos el archivo
    with open(KEYSTORE_FILE, "w", encoding="utf-8") as file:
        json.dump(keystore_data, file, indent=4)


# ==========================================
# ================ LOAD ===================
# ==========================================

def load_keystore(password):

    # Si no existe, devolvemos un diccionario vacio
    if not os.path.exists(KEYSTORE_FILE):
        return {}

    try:

        with open(KEYSTORE_FILE, "r", encoding="utf-8") as file:
            keystore_data = json.load(file)

        # Recuperamos salt
        salt = base64.b64decode(
            keystore_data["salt"]
        )

        # Recuperamos datos cifrados
        encrypted_data = keystore_data["data"]

        # Generamos la misma clave
        key = derive_key(password, salt)

        # Creamos Fernet
        fernet = Fernet(key)

        # Desciframos
        decrypted_data = fernet.decrypt(
            encrypted_data.encode()
        )

        # Convertimos a diccionario
        return json.loads(
            decrypted_data.decode()
        )

    except InvalidToken:
        raise ValueError("Contraseña incorrecta")

    except (
        json.JSONDecodeError,
        KeyError,
        ValueError
    ):
        raise ValueError(
            "El KeyStore esta corrupto"
        )


# ==========================================
# ================= SAVE ==================
# ==========================================

def save_key(
    alias,
    private_key,
    subject,
    password
):

    data = load_keystore(password)

    # Comprobamos alias
    if alias in data:
        raise ValueError(
            "El alias ya existe"
        )

    # Convertimos clave privada a PEM
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    # Guardamos la informacion
    data[alias] = {
        "private_key": private_key_pem,
        "subject": subject.rfc4514_string()
    }

    # Guardamos KeyStore
    save_keystore(
        data,
        password
    )


# ==========================================
# ============ ALIAS EXISTS ===============
# ==========================================

def alias_exists(alias, password):

    data = load_keystore(password)

    return alias in data


# ==========================================
# ============= LIST ALIASES ==============
# ==========================================

def list_aliases(password):

    data = load_keystore(password)

    return list(data.keys())


# ==========================================
# ================= GET ===================
# ==========================================

def get_key(alias, password):

    data = load_keystore(password)

    if alias not in data:
        raise ValueError(
            "El alias no existe"
        )

    return data[alias]