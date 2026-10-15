
# para poder trabajar con archivos, carpetas, json, cifrar contenido,
# convertir datos binarios a texto y utilizar funciones de cryptography
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

# donde se guardaran los datos del keystore
DATA_DIR = "data"

# ruta completa del archivo donde se guardaran las claves cifradas
KEYSTORE_FILE = os.path.join(DATA_DIR, "keystore.enc")

# definir el numero de iteraciones que utilizara PBKDF2
# cuantas mas iteraciones, mas dificil sera probar contrasenas
ITERATIONS = 600000


# ==========================================
# ============== CREATE ====================
# ==========================================

def create_keystore():
    # crear la carpeta de datos si no existe
    # exist_ok evita que de error si la carpeta ya esta creada
    os.makedirs(DATA_DIR, exist_ok=True)


# ==========================================
# ============== DERIVE KEY ================
# ==========================================

def derive_key(password, salt):
    # recibe la contrasena y el salt
    # el salt sirve para que la misma contrasena genere claves diferentes
    # utiliza PBKDF2 para obtener una clave a partir de la contrasena
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # algoritmo hash que se utilizara
        length=32,                  # longitud de la clave en bytes
        salt=salt,                  # valor aleatorio que se utiliza en el proceso
        iterations=ITERATIONS       # numero de iteraciones del algoritmo
    )

    # convertir la contrasena a bytes y generar la clave
    key = kdf.derive(password.encode("utf-8"))

    # fernet necesita la clave codificada en base64 url-safe
    return base64.urlsafe_b64encode(key)


# ==========================================
# ============== SAVE STORE =================
# ==========================================

# recibe los datos y la contrasena
# convierte los datos a json, los cifra y los guarda en el archivo
# el salt se guarda fuera de los datos cifrados para poder recuperar la clave


def save_keystore(data, password):
    # crear la carpeta de datos si no existe
    create_keystore()

    # comprobar si ya existe el almacen
    # si existe, recuperar el salt que ya tenia
    # asi podemos guardar nuevas claves sin perder las anteriores
    if os.path.exists(KEYSTORE_FILE):
        with open(KEYSTORE_FILE, "r", encoding="utf-8") as file:
            stored = json.load(file)

        # recuperar el salt y convertirlo de base64 a bytes
        salt = base64.b64decode(stored["salt"], validate=True)
    else:
        # generar un salt aleatorio de 16 bytes si es un almacen nuevo
        salt = os.urandom(16)

    # generar la clave de cifrado utilizando la contrasena y el salt
    key = derive_key(password, salt)

    # crear el objeto que se encargara de cifrar y descifrar
    fernet = Fernet(key)

    # convertir los datos a json y despues a bytes
    json_data = json.dumps(data).encode("utf-8")

    # cifrar los datos para que no se puedan leer directamente
    encrypted_data = fernet.encrypt(json_data)

    # preparar la informacion que se guardara en el archivo
    # el salt se guarda en base64 y los datos cifrados como texto
    keystore_data = {
        "salt": base64.b64encode(salt).decode("ascii"),
        "data": encrypted_data.decode("ascii")
    }

    # abrir el archivo y guardar la informacion en formato json
    # indent=4 sirve para que el contenido quede mejor organizado
    with open(KEYSTORE_FILE, "w", encoding="utf-8") as file:
        json.dump(keystore_data, file, indent=4)


# ==========================================
# ============== LOAD STORE =================
# ==========================================

# recibe la contrasena y busca el archivo data/keystore.enc
# si el archivo no existe, lanza un error
# si existe y la contrasena es correcta, recupera y descifra los datos
# si la contrasena es incorrecta o el archivo esta danado, lanza un error

def load_keystore(password):
    # comprobar que el almacen existe antes de intentar leerlo
    # no se crea un almacen nuevo automaticamente al leerlo
    if not os.path.exists(KEYSTORE_FILE):
        raise FileNotFoundError(
            "El KeyStore no existe. Genera primero un par de claves."
        )

    try:
        # abrir el archivo y leer el contenido json
        with open(KEYSTORE_FILE, "r", encoding="utf-8") as file:
            stored = json.load(file)

        # recuperar el salt y los datos cifrados
        salt = base64.b64decode(stored["salt"], validate=True)
        encrypted_data = stored["data"]

        # comprobar que el salt tiene la longitud correcta
        # y que los datos cifrados estan guardados como texto
        if len(salt) != 16 or not isinstance(encrypted_data, str):
            raise ValueError("Estructura incorrecta")

        # generar la misma clave utilizando la contrasena y el salt
        key = derive_key(password, salt)

        # crear el objeto que permitira descifrar los datos
        fernet = Fernet(key)

        # convertir los datos cifrados a bytes y descifrarlos
        decrypted_data = fernet.decrypt(encrypted_data.encode("ascii"))

        # convertir los datos descifrados de bytes a texto y leer el json
        data = json.loads(decrypted_data.decode("utf-8"))

        # comprobar que los datos recuperados tienen el formato esperado
        if not isinstance(data, dict):
            raise ValueError("El contenido no es un diccionario")

        # devolver los datos del almacen para poder utilizarlos
        return data

    # se ejecuta si la contrasena es incorrecta o los datos no se pueden descifrar
    except InvalidToken:
        raise ValueError("Contrasena incorrecta o KeyStore danado")

    # controlar errores relacionados con el formato o la estructura del archivo
    except (json.JSONDecodeError, KeyError, TypeError,
            UnicodeDecodeError, base64.binascii.Error):
        raise ValueError("El KeyStore esta danado o tiene un formato incorrecto")

    # controlar errores al acceder o leer el archivo
    except (OSError, UnicodeError):
        raise ValueError("No se ha podido leer el KeyStore")


# ==========================================
# ============== SAVE KEY ==================
# ==========================================

def save_key(alias, private_key, subject, password):
    # comprobar que el alias no este vacio
    if not alias or not alias.strip():
        raise ValueError("El alias no puede estar vacio")

    # comprobar que se haya introducido una contrasena
    if not password:
        raise ValueError("La contrasena no puede estar vacia")

    # si el almacen existe, cargar las claves que ya tiene
    # si no existe, empezar con un diccionario vacio
    if os.path.exists(KEYSTORE_FILE):
        data = load_keystore(password)
    else:
        data = {}

    # comprobar que no exista otra clave con el mismo alias
    if alias in data:
        raise ValueError("El alias ya existe")

    # convertir la clave privada a formato pem
    # pkcs8 es el formato utilizado para guardar la clave privada
    # no se cifra aqui porque despues se cifra todo el contenido del almacen
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("ascii")

    # guardar la clave privada y los datos del propietario
    # el subject se convierte a texto para poder almacenarlo
    data[alias] = {
        "private_key": private_key_pem,
        "subject": subject.rfc4514_string()
    }

    # guardar todas las claves en el almacen cifrado
    save_keystore(data, password)


# ==========================================
# ============== ALIAS EXISTS ==============
# ==========================================

def alias_exists(alias, password):
    # cargar los datos del almacen utilizando la contrasena
    data = load_keystore(password)

    # devolver true si el alias existe y false si no existe
    return alias in data


# ==========================================
# ============== LIST ALIASES ===============
# ==========================================

def list_aliases(password):
    # cargar los datos del almacen utilizando la contrasena
    data = load_keystore(password)

    # devolver una lista con los nombres de todos los alias guardados
    return list(data.keys())


# ==========================================
# ============== GET KEY ===================
# ==========================================

def get_key(alias, password):
    # cargar los datos del almacen utilizando la contrasena
    data = load_keystore(password)

    # comprobar que el alias solicitado existe
    if alias not in data:
        raise ValueError("El alias no existe")

    # devolver los datos guardados para ese alias
    return data[alias]
