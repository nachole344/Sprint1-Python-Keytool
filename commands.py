
# implementacion de los comandos del simulador (uno por funcion)
# cada comando recibe las opciones leidas en mykeytool.py (o None si se llama desde el menu)
# y devuelve 0 si todo ha ido bien o 1 si ha habido un error controlado

import base64
from dataclasses import fields
import datetime
import os
import secrets
import ssl
import sys
from functools import wraps
from getpass import getpass

from certificates import (
    load_certificate_file, load_certificate_pem, load_crl_file, write_certificate,
    fingerprint_sha256, is_self_signed, is_signed_by, same_public_key,
    show_certificate_info, show_crl_info
)
from crypto_utils import (
    generate_rsa_key, create_subject, parse_dname, load_private_key, private_key_to_pem,
    create_self_signed_certificate, issue_certificate
)
from csr import generate_csr_for_alias, save_csr
from keystore import (
    KEYSTORE_FILE, ITERATIONS, PRIVATE_KEY_ENTRY, TRUSTED_CERT_ENTRY, SECRET_KEY_ENTRY,
    keystore_exists, load_keystore, save_keystore, save_key, add_entry, replace_entry,
    delete_entry, rename_entry, change_store_password, get_key, alias_exists,
    entry_type, certificate_to_pem, now_text, output_path, input_path
)
from verify_csr import verify_csr, show_csr_info


VERSION = "1.0"
KEY_SIZES = (2048, 3072, 4096)
AES_SIZES = (128, 192, 256)
YES = ("s", "si", "sí", "y", "yes")


# ==========================================
# ============== UTILIDADES ================
# ==========================================

def opt(opts, name):
    # obtener el valor de una opcion de la linea de comandos
    # getattr permite devolver none si opts no contiene esa opcion
    # esto tambien permite utilizar las funciones desde el menu interactivo
    return getattr(opts, name, None)


def fail(message):
    # mostrar un mensaje de error controlado
    # devolver 1 para indicar que el comando ha terminado con un error
    print(f"Error: {message}")
    return 1


def safe(command):
    # decorador que protege los comandos frente a errores esperados
    # permite reutilizar el mismo control de errores en varias funciones
    @wraps(command)
    def wrapper(*args, **kwargs):
        try:
            # ejecutar el comando original con sus argumentos
            return command(*args, **kwargs)
        except (ValueError, OSError) as error:
            # controlar errores de validacion y operaciones con archivos
            return fail(error)
        except (TypeError, KeyError):
            # controlar datos incorrectos o incompletos del keystore
            return fail("los datos almacenados en el KeyStore no son válidos.")

    return wrapper


def ask_password(given=None, confirm=False, label="Contraseña del KeyStore"):
    # utilizar la contraseña recibida por parametros o solicitarla por teclado
    # getpass evita mostrar la contraseña mientras se escribe
    password = given if given is not None else getpass(f"{label}: ")

    # no permitir contraseñas vacias
    if not password:
        print("Error: la contraseña no puede estar vacía.")
        return None

    # comprobar que la contraseña tenga la longitud minima establecida
    if len(password) < 6:
        print("Error: la contraseña debe tener al menos 6 caracteres.")
        return None

    # si se esta creando un almacen nuevo, pedir la contraseña dos veces
    # no se solicita confirmacion cuando la contraseña viene por parametros
    if confirm and given is None:
        if getpass("Repite la contraseña: ") != password:
            print("Error: las contraseñas no coinciden.")
            return None

    return password


def ask_key_password(keystore_password, given=None, confirm=False):
    # solicitar la contraseña que protege la clave privada de un alias
    # si se pulsa enter sin escribir nada, utilizar la contraseña del keystore
    if given is not None:
        key_password = given
    else:
        key_password = getpass("Contraseña del alias (ENTER = la misma que la del KeyStore): ")

    # devolver la contraseña del almacen si no se ha escrito otra
    if not key_password:
        return keystore_password

    # comprobar la longitud minima de la contraseña del alias
    if len(key_password) < 6:
        print("Error: la contraseña debe tener al menos 6 caracteres.")
        return None

    # confirmar la contraseña cuando se esta creando una nueva
    if confirm and given is None:
        if getpass("Repite la contraseña del alias: ") != key_password:
            print("Error: las contraseñas no coinciden.")
            return None

    return key_password


def ask_alias(given=None, label="Alias"):
    # obtener el alias desde los parametros o preguntarlo por teclado
    alias = given if given is not None else input(f"{label}: ")

    # eliminar espacios al principio y al final
    alias = alias.strip()

    # no permitir nombres vacios
    if not alias:
        print("Error: el alias no puede estar vacío.")
        return None

    return alias


def ask_subject_data():
    # solicitar los datos que identifican al titular del certificado
    # estos campos forman el nombre distinguido o distinguished name (dn)
    print("\\n=== Datos del titular ===")

    # Se pregunan cada uno de los datos (entre corchetes se avisa cúal es la opción por defecto)
    fields = {
        "CN": input("CN (Common Name)\n [Unknown]: ").strip(),
        "OU": input("OU (Organizational Unit)\n [Unknown]: ").strip(),
        "O": input("O (Organization)\n [Unknown]: ").strip(),
        "L": input("L (Locality)\n [Unknown]: ").strip(),
        "ST": input("ST (State/Province)\n [Unknown]: ").strip(),
        "C": input("C (Country)\n [Unknown]: ").strip().upper(),
    }

    # Si un campo se deja vacio, se le pondra "Unknown" por defecto (a excepcion del campo Country)
    for name, value in fields.items():
        if not value:
            fields[name] = "Unknown"

    # Si el campo Country [C] existe, comprueba que tenga 2 caracteres exactos
    if fields["C"] != "Unknown" and len(fields["C"]) != 2:
        print("Error: el campo C debe tener exactamente 2 caracteres.")
        return None

    return fields


def open_store(opts):
    # comprobar que existe el keystore y obtener la contraseña
    # devuelve la ruta y la contraseña si todo es correcto
    # devuelve none si no se puede continuar
    path = opt(opts, "keystore")

    if not keystore_exists(path):
        print(f"Error: el KeyStore no existe ({path or KEYSTORE_FILE}). Genera primero un par de claves.")
        return None

    password = ask_password(opt(opts, "storepass"))
    if not password:
        return None

    return path, password


def safe_name(alias):
    # convertir un alias en un nombre de archivo seguro
    # conservar letras, numeros, guiones, guiones bajos y puntos
    # sustituir otros caracteres por guiones bajos
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in alias)


def required_file(opts, *names):
    # buscar el nombre de archivo en las opciones indicadas
    # tambien comprobar la opcion generica archivo
    # devolver el primer valor encontrado o none si falta
    for name in names + ("archivo",):
        value = opt(opts, name)
        if value:
            return value

    return None


def get_certificate(entry):
    # obtener el certificado asociado a una entrada del keystore
    # algunas entradas, como las claves secretas, no tienen certificado
    pem = entry.get("certificate")
    return load_certificate_pem(pem) if pem else None


def check_validity(days):
    # utilizar 90 dias como validez predeterminada
    if days is None:
        return 90

    # impedir que se creen certificados con una validez inferior a un dia
    if days < 1:
        raise ValueError("La validez debe ser de al menos 1 día")

    return days


# ==========================================
# ============== GENKEYPAIR ================
# ==========================================

@safe
def genkeypair(opts=None):
    # generar una clave privada rsa y su correspondiente clave publica
    print("=== Generación de par de claves ===")

    # obtener la ruta del keystore si se ha indicado
    path = opt(opts, "keystore")

    # comprobar que el algoritmo solicitado sea rsa
    if (opt(opts, "keyalg") or "RSA").upper() != "RSA":
        return fail("solo se admite el algoritmo RSA (-keyalg RSA)")

    # utilizar 2048 bits por defecto y aceptar solo los tamaños permitidos
    key_size = opt(opts, "keysize") or 2048
    if key_size not in KEY_SIZES:
        return fail("tamaño de clave no válido; usa 2048 (por defecto), 3072 o 4096")

    # obtener la duracion del certificado o utilizar el valor predeterminado
    days = check_validity(opt(opts, "validity"))

    # pedir confirmacion de la contraseña si el keystore todavia no existe
    password = ask_password(opt(opts, "storepass"), confirm=not keystore_exists(path))
    if not password:
        return 1

    # obtener el alias con el que se identificara la entrada
    alias = ask_alias(opt(opts, "alias"))
    if not alias:
        return 1

    # impedir que se sobrescriba una entrada que ya utiliza ese alias
    if keystore_exists(path) and alias_exists(alias, password, path):
        return fail("el alias ya existe")

    # solicitar la contraseña que protegera la clave privada
    key_password = ask_key_password(password, opt(opts, "keypass"), confirm=True)
    if not key_password:
        return 1

    # obtener los datos del titular del certificado
    # si se ha indicado -dname, analizar los datos recibidos
    # si no, solicitarlos mediante preguntas interactivas
    if opt(opts, "dname"):
        subject = parse_dname(opt(opts, "dname"))
    else:
        subject_data = ask_subject_data()
        if not subject_data:
            return 1

        # crear el nombre distinguido con los datos introducidos
        subject = create_subject(
            cn=subject_data["CN"],
            ou=subject_data["OU"],
            o=subject_data["O"],
            l=subject_data["L"],
            st=subject_data["ST"],
            c=subject_data["C"]
        )

    # DN en formato RFC4514 para mostrarlo al usuario y pedir confirmacion
    text_subject = subject.rfc4514_string()
    if subject_data["C"] == "Unknown":
        text_subject += ",C=Unknown"

    # Se pide confirmación de los datos antes de hacer un guardao definitivo
    print(f"¿Es {text_subject} correcto? [y/n]")
    op = input("[no]: ").lower() # Entre corchetes se avisa cúal es la opción por defecto
    if op == "n":
        print("Par de claves no generado.")
        return 1
    elif not (op == "y" or op == "s"):
        fail("opción no válida introducida.")
        print("Par de claves no generado.")
        return 1
    
    private_key = generate_rsa_key(key_size)

    # crear un certificado autofirmado para asociarlo al nuevo par de claves
    # este certificado todavia no ha sido validado por una autoridad certificadora
    certificate = create_self_signed_certificate(private_key, subject, days)

    # guardar la clave privada protegida y el certificado en el keystore
    save_key(alias, private_key, subject, password, key_password, certificate, path)

    # mostrar un resumen de la operacion realizada
    print()
    print("Par de claves RSA generado correctamente.")
    print(f"Alias: {alias}")
    print(f"Tamaño de clave: {private_key.key_size} bits")
    print(f"DN: {subject.rfc4514_string()}")
    print(f"Certificado autofirmado válido durante {days} días.")
    print("Clave guardada correctamente en el KeyStore.")
    return 0


# ==========================================
# ================= LIST ===================
# ==========================================

def print_entry(alias, entry, verbose):
    # identificar el tipo de entrada y comprobar si tiene certificado
    kind = entry_type(entry)
    certificate = get_certificate(entry)

    # mostrar el alias, la fecha de creacion y el tipo de entrada
    print(f"{alias}, {entry.get('created', 'fecha desconocida')}, {kind}")

    # las claves secretas no tienen certificado y no se muestran directamente
    if kind == SECRET_KEY_ENTRY:
        print(f"  Clave secreta {entry.get('algorithm')} de {entry.get('key_size')} bits (no se muestra)")
        return

    # mostrar la huella del certificado si existe
    if certificate:
        print(f"  Huella del certificado (SHA-256): {fingerprint_sha256(certificate)}")
    else:
        print("  Sin certificado asociado")

    # mostrar mas informacion cuando se solicita el modo detallado (-v)
    if verbose:
        if kind == PRIVATE_KEY_ENTRY:
            size = entry.get("key_size")

            # indicar que la clave privada esta protegida sin revelar su contenido
            print(f"  Clave privada: RSA {size} bits (protegida, no se muestra)" if size
                  else "  Clave privada: protegida, no se muestra")

            # mostrar el titular guardado si la entrada todavia no tiene certificado
            if not certificate:
                print(f"  Titular: {entry.get('subject')}")

        # mostrar los datos completos del certificado cuando esta disponible
        if certificate:
            show_certificate_info(certificate, "  ")


@safe
def list_entries(opts=None):
    # abrir el keystore y comprobar la contraseña
    store = open_store(opts)
    if not store:
        return 1

    path, password = store

    # descifrar y cargar las entradas del almacen
    data = load_keystore(password, path)

    # si se indica un alias, mostrar solo esa entrada
    alias = opt(opts, "alias")

    if alias is not None:
        if alias not in data:
            return fail("el alias no existe")

        items = [(alias, data[alias])]
    else:
        # si no se indica alias, preparar todas las entradas para mostrarlas
        items = list(data.items())

    # mostrar informacion general del almacen
    print("Tipo de almacén: KeyStore cifrado (PBKDF2 + Fernet)")
    print(f"Archivo: {path or KEYSTORE_FILE}")
    print(f"Número de entradas: {len(items)}")

    # recorrer las entradas y mostrar su informacion
    for entry_alias, entry in items:
        print()
        print_entry(entry_alias, entry, bool(opt(opts, "v")))

    return 0


# ==========================================
# =============== CERTREQ ==================
# ==========================================

@safe
def certreq(opts=None):
    # generar una solicitud de firma de certificado (csr)
    print("=== Generación de solicitud de firma de certificado (CSR) ===")

    # comprobar que existe el almacen antes de continuar
    store = open_store(opts)
    if not store:
        return 1

    path, password = store

    # identificar la entrada cuya clave privada se utilizara para firmar la csr
    alias = ask_alias(opt(opts, "alias"))
    if not alias:
        return 1

    # solicitar la contraseña que permite acceder a la clave privada
    key_password = ask_key_password(password, opt(opts, "keypass"))
    if not key_password:
        return 1

    print()
    print("Recuperando clave del KeyStore...")

    # generar la csr utilizando la clave y el titular del alias
    csr = generate_csr_for_alias(alias, password, key_password, path)

    # guardar la solicitud en el archivo indicado o utilizar el alias como nombre
    filepath = save_csr(csr, opt(opts, "file") or safe_name(alias) + ".csr")

    print()
    print("CSR generada correctamente.")
    print("Archivo:", filepath)
    return 0


@safe
def printcertreq(opts=None):
    # mostrar la informacion de una solicitud de certificado existente
    filename = required_file(opts, "file")
    if not filename:
        return fail("indica el archivo CSR: -printcertreq -file ARCHIVO.csr")

    # cargar la csr y comprobar que su firma sea valida
    csr = verify_csr(input_path(filename))

    # mostrar los datos del titular y de la solicitud
    show_csr_info(csr)
    return 0


# ==========================================
# ========== EXPORTCERT / EXPORT ===========
# ==========================================

@safe
def exportcert(opts=None):
    # exportar el certificado asociado a un alias a un archivo externo
    store = open_store(opts)
    if not store:
        return 1

    path, password = store

    # identificar la entrada que contiene el certificado
    alias = ask_alias(opt(opts, "alias"))
    if not alias:
        return 1

    entry = get_key(alias, password, path)
    certificate = get_certificate(entry)

    # impedir la exportacion si la entrada no tiene certificado
    if certificate is None:
        return fail("el alias no tiene certificado asociado (solo hay clave privada o clave secreta)")

    # elegir el nombre del archivo y el formato de salida
    filepath = output_path(opt(opts, "file") or safe_name(alias) + ".crt")
    write_certificate(certificate, filepath, bool(opt(opts, "rfc")))

    # informar de la ruta y el formato utilizados
    print(f"Certificado almacenado en el archivo: {filepath}")
    print("Formato:", "PEM (-rfc)" if opt(opts, "rfc") else "DER (binario)")

    # solo se exporta el certificado y su clave publica, nunca la clave privada
    print("Solo se exporta el certificado (clave pública); la clave privada no sale del KeyStore.")
    return 0

# ==========================================
# ========= DELETE / CHANGEALIAS ===========
# ==========================================

@safe
def delete(opts=None):
    # eliminar una entrada del keystore mediante su alias
    store = open_store(opts)
    if not store:
        return 1

    path, password = store

    # obtener el alias de la entrada que se quiere eliminar
    alias = ask_alias(opt(opts, "alias"))
    if not alias:
        return 1

    # eliminar la entrada despues de comprobar el acceso al almacen
    delete_entry(alias, password, path)
    print(f"Entrada {alias} eliminada del KeyStore.")
    return 0


@safe
def changealias(opts=None):
    # cambiar el nombre de un alias sin cambiar el contenido de la entrada
    store = open_store(opts)
    if not store:
        return 1

    path, password = store

    # solicitar el alias actual
    alias = ask_alias(opt(opts, "alias"))
    if not alias:
        return 1

    # solicitar el nuevo nombre que tendra la entrada
    new_alias = ask_alias(opt(opts, "destalias"), "Alias nuevo")
    if not new_alias:
        return 1

    # renombrar la entrada dentro del almacen
    rename_entry(alias, new_alias, password, path)
    print(f"Alias cambiado: {alias} -> {new_alias}")
    return 0

# ==========================================
# ================ PRINTCERT ===============
# ==========================================

@safe
def printcert(opts=None):
    # leer y mostrar los datos de un certificado desde un archivo
    filename = required_file(opts, "file")
    if not filename:
        return fail("indica el archivo del certificado: -printcert -file ARCHIVO.crt")

    # cargar el certificado en formato pem o der y mostrar sus datos
    show_certificate_info(load_certificate_file(input_path(filename)))
    return 0


@safe
def printcrl(opts=None):
    # mostrar el contenido de una lista de revocacion de certificados
    filename = required_file(opts, "file")
    if not filename:
        return fail("indica el archivo de la CRL: -printcrl -file ARCHIVO.crl")

    # cargar la crl y mostrar el emisor, las fechas y los certificados revocados
    show_crl_info(load_crl_file(input_path(filename)))
    return 0


# ==========================================
# ========= STOREPASSWD / KEYPASSWD ========
# ==========================================

def ask_new_password(given, label):
    # solicitar una nueva contraseña o utilizar la recibida por parametros
    password = given if given is not None else getpass(f"{label}: ")

    # comprobar que no este vacia y que cumpla la longitud minima
    if not password or len(password) < 6:
        print("Error: la contraseña nueva debe tener al menos 6 caracteres.")
        return None

    # pedir confirmacion cuando la contraseña se introduce por teclado
    if given is None and getpass("Repite la contraseña nueva: ") != password:
        print("Error: las contraseñas no coinciden.")
        return None

    return password


@safe
def storepasswd(opts=None):
    # cambiar la contraseña que protege todo el keystore
    store = open_store(opts)
    if not store:
        return 1

    path, password = store

    # solicitar y validar la nueva contraseña del almacen
    new_password = ask_new_password(opt(opts, "new"), "Nueva contraseña del KeyStore")
    if not new_password:
        return 1

    # volver a guardar el almacen utilizando la contraseña nueva
    change_store_password(password, new_password, path)
    print("Contraseña del KeyStore cambiada. El archivo se ha cifrado de nuevo con la contraseña nueva.")
    return 0


@safe
def keypasswd(opts=None):
    # cambiar la contraseña que protege la clave privada de un alias
    store = open_store(opts)
    if not store:
        return 1

    path, password = store

    # localizar la entrada cuya contraseña se quiere cambiar
    alias = ask_alias(opt(opts, "alias"))
    if not alias:
        return 1

    entry = get_key(alias, password, path)

    # solo las entradas que contienen claves privadas admiten esta operacion
    if entry_type(entry) != PRIVATE_KEY_ENTRY:
        return fail("solo se puede cambiar la contraseña de entradas con clave privada")

    # solicitar la contraseña actual de la clave privada
    old_key_password = ask_key_password(password, opt(opts, "keypass"))
    if not old_key_password:
        return 1

    # solicitar la contraseña nueva
    new_key_password = ask_new_password(opt(opts, "new"), "Nueva contraseña del alias")
    if not new_key_password:
        return 1

    # descifrar la clave privada utilizando la contraseña antigua
    private_key = load_private_key(entry["private_key"], old_key_password)

    # volver a cifrar la misma clave privada con la contraseña nueva
    entry["private_key"] = private_key_to_pem(private_key, new_key_password)

    # guardar los cambios en el almacen
    replace_entry(alias, entry, password, path)
    print(f"Contraseña del alias {alias} cambiada.")
    return 0
# ==========================================
# ========= IMPORTCERT / IMPORT ============
# ==========================================

def issuer_in_store(certificate, data, skip_alias):
    # buscar un certificado emisor dentro del keystore
    # se utiliza para comprobar si existe un certificado que haya firmado al importado
    for alias, entry in data.items():

        # saltar el alias indicado y las entradas que no contienen certificado
        if alias == skip_alias or not entry.get("certificate"):
            continue

        # cargar el certificado candidato a emisor
        issuer = load_certificate_pem(entry["certificate"])

        # comprobar que el nombre del emisor coincide y que la firma es valida
        if issuer.subject == certificate.issuer and is_signed_by(certificate, issuer):
            return True

    # no se ha encontrado ningun certificado que permita comprobar la emision
    return False


@safe
def importcert(opts=None):
    # importar un certificado desde un archivo al keystore
    filename = required_file(opts, "file")
    if not filename:
        return fail("indica el certificado a importar: -importcert -file ARCHIVO.crt")

    # cargar el certificado y detectar automaticamente pem o der
    certificate = load_certificate_file(input_path(filename))
    path = opt(opts, "keystore")
    exists = keystore_exists(path)

    # pedir la contraseña del almacen
    # si es nuevo, solicitar tambien la confirmacion
    password = ask_password(opt(opts, "storepass"), confirm=not exists)
    if not password:
        return 1

    # obtener el alias con el que se guardara el certificado
    alias = ask_alias(opt(opts, "alias"))
    if not alias:
        return 1

    # cargar las entradas existentes o crear un diccionario vacio
    data = load_keystore(password, path) if exists else {}

    if alias in data:
        # si el alias ya existe, puede ser una clave privada que espera su certificado firmado
        entry = data[alias]

        # comprobar que la entrada sea un par de claves
        if entry_type(entry) != PRIVATE_KEY_ENTRY:
            return fail("el alias ya existe y no es un par de claves")

        # comprobar que la entrada contiene la clave publica necesaria para comparar
        if "public_key" not in entry:
            return fail("entrada antigua sin clave pública guardada; vuelve a generar el par de claves")

        # verificar que el certificado corresponde a la clave creada originalmente
        if not same_public_key(certificate, entry["public_key"]):
            return fail("la clave pública del certificado no coincide con la del alias")

        # si no es autofirmado, comprobar que se conoce su emisor en el almacen
        if not is_self_signed(certificate) and not issuer_in_store(certificate, data, alias):
            return fail("no se puede establecer la cadena: falta en el KeyStore el certificado del emisor")

        # asociar el certificado recibido a la clave privada existente
        entry["certificate"] = certificate_to_pem(certificate)
        save_keystore(data, password, path)
        print(f"Respuesta de certificado instalada en el alias {alias}.")
        return 0

    # si el alias es nuevo, se propone guardar el certificado como certificado de confianza
    print("Certificado a importar:")
    show_certificate_info(certificate, "  ")

    # solicitar confirmacion antes de confiar en un certificado desconocido
    if not opt(opts, "noprompt"):
        answer = input("¿Confiar en este certificado? [no]: ").strip().lower()
        if answer not in YES:
            print("El certificado no se ha añadido.")
            return 1

    # guardar los datos del certificado como una nueva entrada de confianza
    # esta entrada contiene el certificado publico, no una clave privada
    data[alias] = {
        "type": TRUSTED_CERT_ENTRY,
        "certificate": certificate_to_pem(certificate),
        "subject": certificate.subject.rfc4514_string(),
        "created": now_text(),
    }

    # guardar el almacen actualizado
    save_keystore(data, password, path)
    print(f"Certificado añadido al KeyStore como certificado de confianza ({alias}).")
    return 0

# ==========================================
# ================ GENCERT =================
# ==========================================

@safe
def gencert(opts=None):
    # emitir un certificado a partir de una solicitud csr
    # el emisor firma el nuevo certificado con su clave privada
    infile = required_file(opts, "infile")
    if not infile:
        return fail("indica la CSR con -infile ARCHIVO.csr")

    # comprobar cuantos dias sera valido el certificado emitido
    days = check_validity(opt(opts, "validity"))

    # abrir el almacen que contiene la clave del emisor
    store = open_store(opts)
    if not store:
        return 1

    path, password = store

    # identificar el alias que actuara como emisor del certificado
    alias = ask_alias(opt(opts, "alias"), "Alias del emisor")
    if not alias:
        return 1

    entry = get_key(alias, password, path)
    issuer_certificate = get_certificate(entry)

    # el emisor necesita una clave privada y un certificado asociado
    if entry_type(entry) != PRIVATE_KEY_ENTRY or issuer_certificate is None:
        return fail("el alias del emisor necesita clave privada y certificado")

    # comprobar que el certificado del emisor se encuentra dentro de su periodo de validez
    now = datetime.datetime.now(datetime.timezone.utc)
    if not issuer_certificate.not_valid_before_utc <= now <= issuer_certificate.not_valid_after_utc:
        return fail("el certificado del emisor está caducado o todavía no es válido")

    # obtener la contraseña necesaria para utilizar la clave privada del emisor
    key_password = ask_key_password(password, opt(opts, "keypass"))
    if not key_password:
        return 1

    # cargar la csr y comprobar su firma antes de emitir el certificado
    csr = verify_csr(input_path(infile))

    # recuperar la clave privada del emisor para firmar el certificado nuevo
    issuer_key = load_private_key(entry["private_key"], key_password)

    # crear el certificado con los datos de la csr y la firma del emisor
    certificate = issue_certificate(csr, issuer_key, issuer_certificate, days)

    # generar el nombre del archivo de salida si no se ha indicado uno
    base = os.path.splitext(os.path.basename(infile))[0]
    filepath = output_path(opt(opts, "outfile") or safe_name(base) + ".crt")

    # guardar el certificado en pem o der segun la opcion seleccionada
    write_certificate(certificate, filepath, bool(opt(opts, "rfc")))

    # mostrar un resumen del certificado emitido
    print("Certificado emitido correctamente.")
    print(f"Titular: {certificate.subject.rfc4514_string()}")
    print(f"Emisor: {certificate.issuer.rfc4514_string()}")
    print(f"Válido durante {days} días.")
    print(f"Archivo: {filepath}")

    # aclarar que esta emision sirve para practicar y no equivale a una ca real
    print("Aviso: el emisor es un alias de este KeyStore, no una CA real; solo sirve para practicar.")
    return 0

# ==========================================
# ============== GENSECKEY =================
# ==========================================

@safe
def genseckey(opts=None):
    # generar una clave secreta para cifrado simetrico mediante aes
    path = opt(opts, "keystore")

    # comprobar que el algoritmo solicitado sea aes
    if (opt(opts, "keyalg") or "AES").upper() != "AES":
        return fail("solo se admite el algoritmo AES (-keyalg AES)")

    # seleccionar el tamaño de la clave o utilizar 256 bits por defecto
    key_size = opt(opts, "keysize") or 256
    if key_size not in AES_SIZES:
        return fail("tamaño no válido para AES; usa 128, 192 o 256 (por defecto 256)")

    # pedir la contraseña del almacen y confirmarla si es nuevo
    password = ask_password(opt(opts, "storepass"), confirm=not keystore_exists(path))
    if not password:
        return 1

    # identificar la clave mediante un alias
    alias = ask_alias(opt(opts, "alias"))
    if not alias:
        return 1

    # generar bytes aleatorios seguros para la clave aes
    # el numero de bytes depende del tamaño seleccionado en bits
    secret = secrets.token_bytes(key_size // 8)

    # codificar la clave en base64 para poder guardarla como texto
    # el contenido queda protegido por el cifrado del keystore
    add_entry(alias, {
        "type": SECRET_KEY_ENTRY,
        "algorithm": "AES",
        "key_size": key_size,
        "secret_key": base64.b64encode(secret).decode("ascii"),
        "created": now_text(),
    }, password, path)

    # informar de que la clave se ha guardado sin mostrar su valor
    print(f"Clave secreta AES de {key_size} bits guardada con el alias {alias}.")
    print("La clave no se muestra. Está protegida por la contraseña del KeyStore.")
    return 0


# ==========================================
# ============ IMPORTKEYSTORE ==============
# ==========================================

@safe
def importkeystore(opts=None):
    # copiar entradas de un keystore de origen a otro de destino
    src_path = opt(opts, "srckeystore")
    dest_path = opt(opts, "destkeystore")

    # comprobar que se ha indicado el almacen de origen
    if not src_path:
        return fail("indica el KeyStore de origen con -srckeystore ARCHIVO")

    # comprobar que el archivo de origen existe
    if not keystore_exists(src_path):
        return fail(f"el KeyStore de origen no existe ({src_path})")

    # impedir que el origen y el destino sean el mismo archivo
    if os.path.abspath(src_path) == os.path.abspath(dest_path or KEYSTORE_FILE):
        return fail("el origen y el destino son el mismo archivo")

    # pedir la contraseña necesaria para descifrar el almacen de origen
    src_password = ask_password(opt(opts, "srcstorepass"), label="Contraseña del KeyStore de origen")
    if not src_password:
        return 1

    # cargar las entradas del almacen de origen
    src_data = load_keystore(src_password, src_path)

    # comprobar si existe el almacen de destino
    dest_exists = keystore_exists(dest_path)

    # pedir la contraseña del destino y confirmarla si es un almacen nuevo
    dest_password = ask_password(
        opt(opts, "deststorepass"), confirm=not dest_exists,
        label="Contraseña del KeyStore de destino"
    )
    if not dest_password:
        return 1

    # cargar las entradas existentes en el destino o empezar con un almacen vacio
    dest_data = load_keystore(dest_password, dest_path) if dest_exists else {}

    # si se indica un alias, comprobar que exista en el origen
    src_alias = opt(opts, "srcalias")
    if src_alias is not None and src_alias not in src_data:
        return fail("el alias de origen no existe")

    # seleccionar una entrada concreta o todas las entradas del origen
    aliases = [src_alias] if src_alias is not None else list(src_data)
    imported = 0

    # copiar las entradas seleccionadas sin sobrescribir las que ya existen
    for alias in aliases:
        if alias in dest_data:
            print(f"Aviso: el alias {alias} ya existe en el destino; no se importa.")
        else:
            # copiar la entrada conservando sus datos y su proteccion actual
            dest_data[alias] = src_data[alias]
            imported += 1

    # guardar el destino solo si se ha importado alguna entrada
    if imported:
        save_keystore(dest_data, dest_password, dest_path)

    # mostrar el numero de entradas copiadas
    print(f"Entradas importadas: {imported}")
    return 0


# ==========================================
# ========== SHOWINFO / VERSION ============
# ==========================================

def showinfo(opts=None):
    # mostrar informacion tecnica sobre el funcionamiento del simulador
    print(f"Simulador: mykeytool {VERSION}")

    # indicar el sistema utilizado para cifrar y autenticar el keystore
    print("Cifrado del KeyStore: Fernet (AES-128-CBC + HMAC-SHA256, con autenticación)")

    # mostrar el algoritmo y las iteraciones utilizados para derivar la clave
    print(f"Derivación de clave: PBKDF2-HMAC-SHA256, {ITERATIONS} iteraciones, salt aleatorio de 16 bytes")

    # indicar el formato utilizado para proteger las claves privadas de los alias
    print("Claves privadas de los alias: PKCS#8 cifradas con la contraseña del alias")

    # mostrar los tamaños de clave rsa que admite el simulador
    print(f"Claves asimétricas: RSA {', '.join(str(s) for s in KEY_SIZES)} bits (por defecto 2048); firmas SHA-256")

    # mostrar los tamaños de clave simetrica aes disponibles
    print(f"Claves simétricas: AES {', '.join(str(s) for s in AES_SIZES)} bits (por defecto 256)")

    # indicar la version de python que esta ejecutando el programa
    print(f"Python: {sys.version.split()[0]}")

    # mostrar la version de openssl utilizada por el modulo ssl
    print(f"OpenSSL de Python: {ssl.OPENSSL_VERSION}")

    # indicar si la version de openssl permite utilizar tls 1.3
    print(f"TLS 1.3 disponible: {'sí' if ssl.HAS_TLSv1_3 else 'no'}")
    return 0


def version(opts=None):
    # mostrar la version actual del simulador
    print(f"mykeytool {VERSION} (simulador de Java Keytool en Python)")
    return 0