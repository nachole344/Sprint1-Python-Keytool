# para poder trabajar con archivos, carpetas, json, cifrar contenido,
# convertir datos binarios a texto y cryptography
import os  
import json
import base64

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization

#donde ser guardara (la carpeta dta en el archivo keystore.enc)
DATA_DIR = "data"
KEYSTORE_FILE = os.path.join(DATA_DIR, "keystore.enc")

#definir el numero de iteraciones para PBKDF2
ITERATIONS = 600000

#======================
#========CREATE========
#======================
def create_keystore():
    if not os.path.exists(DATA_DIR): #COMPRUEBA SI EXISTE LA CARPETA DATA
        os.makedirs(DATA_DIR) # sino la crea

#======================
#========DERIVE========
#======================
# recibe password y salt(sirve para q la misma contraseña no produzca siempre el mismo resultado)
#usa PBKDF2 para derivar una clave de cifrado  a partir de la contraseñ
def derive_key(password, salt): 
    kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=ITERATIONS
    )

    key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(key)

#=============================
#========SAVE_KAYSTORE========
#=============================
#data - JSON - UTF-8 - fernet - datos cifrados - keystore.enc (salt fuera de los cifrados para recuperarlo para generar la clvae)
def save_keystore(data, password): 
    create_keystore()

# Generamos un salt aleatorio
    salt = os.urandom(16)

    # Generamos la clave de cifrado utilizando la contraseña
    key = derive_key(password, salt)

    # Creamos el objeto encargado del cifrado
    fernet = Fernet(key)

    # Convertimos los datos a JSON
    json_data = json.dumps(data)

    # Ciframos el JSON
    encrypted_data = fernet.encrypt(json_data.encode())

    # Guardamos el salt y los datos cifrados
    keystore_data = {
        "salt": base64.b64encode(salt).decode(),
        "data": encrypted.data.decode()
    }
    # Escribimos el contenido en el fichero
    with open(KEYSTORE_FILE, "w") as file:
        json.dump(keystore_data, file, indent=4)


#====================
#========LOAS========
#====================

#recibe la contraeña y busca data/keystore.enc
# si no existe lanza error
#si existe y es correcta,  recupera el salt, genera la clave y descifra los datos
# si la cobtraseña es incorrecta, el descifrado falla
# si el contenido no puede cifrarse correctamente, tmb salta erro
def load_keystore(password):
    if not os.path.exists(KEYSTORE_FILE):
        return{}
    try:
        # Abrimos el fichero
        with open(KEYSTORE_FILE, "r") as file:
            keystore_data = json.load(file)

        # Recuperamos el salt
        salt = base64-b64decode(keystore_data["salt"])

        # Recuperamos los datos cifrados
        encrypted_data = keystore_data["data"]

        # Volvemos a generar la clave utilizando
        # la contraseña introducida y el mismo salt
        key = derive_key(password, salt)

        # Creamos el objeto Fernet
        fernet = Fernet(key)

        # Desciframos los datos
        decrypted_data = fernet.decrypt(
            encrypted_data.encode()
        )

        # Convertimos el JSON descifrado en un diccionario
        return json.loads(decrypted_data.decode())

    except InvalidToken: #si la contraseña es incorrecta
        raise ValueError("Contraseña incorrecta")

    except (json.JSONDecodeError, KeyError, ValueError): #si el fichero esta corrupto o estructura incorrecta
        raise ValueError("El KeyStore esta corrupto")


#====================
#========SAVE========
#====================
# guarda la contraseña encriptada dentro del keystore
# ej recibe : alias (pepe), private_key(clave privada),
# subject (nombre comun (CN), organitation unit(OU), organitation(O), locality(L), state o provincie (ST), country(C))
# ej: CN=PEPE OU=DAM O=MONLAU L=BARCELONA ST=BARCELONA C=ES
# y la contraseña
#luego comprueba si existe data/keystore.enc, sino lo crea, y si si lo abre
#luego comprueba si el alias existe, si ya existe no sobreescribe la clave
#luego añade la info
#convierte la info en una estructura que se pueda guardar como JSON (antes de cifrarlo)
def save_key(alias, private_key, subject, password):
    #cargamos el Kaystore que existe
    data = load_keystore(password)

    #comprobar si el alias existe 
    if alias in data:
        raise ValueError("El alias ya existe")

    #convertir la clave privada a formato PEM
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encodign.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algotithm=serialization.NoEncryption()
    ).decode()

    #crear la info que se guarda
    data[alias] = {
        "private_key": private_key_pem,
        "subject": subject
    }

    #guardar de nuevo el keystore
    save_keystore(data, password)



#============================
#========ALIAS_EXISTS========
#============================
#es para comprobar si un alias ya esta en uso
#devuelve true o false/continua o salta error
def alias_exists(alias, password):
    data = load_keystore(password)
    return alias in data

#===================
#========GET========
#===================
#recupera una clave privada concreta
#devuelve los datoas asociados al alias
def get_key(alias, password)
    data = load_keystore(password)

    if alias not in data:
        raise ValueError("El alias no existe")
    
    return data[alias]



#                   save_key()
#        _-_____________-_______________-__
#       alias       private_key     subject
#         -
#   alias existe
#   -          -
#   Si         NO
#   -           -   
# ERROR     convertir clave a PEM  
#               -
#           añadir al diccionario
#               -
#           save_keystore()
#               -
#           cifrar con fernet
#               -
#           data/keystore.enc
#