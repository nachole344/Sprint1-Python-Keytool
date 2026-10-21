
# implementacion de los comandos del simulador (uno por funcion)
# cada comando recibe las opciones leidas en mykeytool.py (o None si se llama desde el menu)
# y devuelve 0 si todo ha ido bien o 1 si ha habido un error controlado

import base64
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
    # leer una opcion; devuelve None si no existe (por ejemplo, si se llama desde el menu)
    return getattr(opts, name, None)


def fail(message):
    print(f"Error: {message}")
    return 1


def safe(command):
    # captura los errores esperados para que ningun comando termine con una traza
    @wraps(command)
    def wrapper(*args, **kwargs):
        try:
            return command(*args, **kwargs)
        except (ValueError, OSError) as error:
            return fail(error)
        except (TypeError, KeyError):
            return fail("los datos almacenados en el KeyStore no son válidos.")

    return wrapper


def ask_password(given=None, confirm=False, label="Contraseña del KeyStore"):
    # si la contraseña viene en la linea de comandos (-storepass) no se pregunta
    password = given if given is not None else getpass(f"{label}: ")

    if not password:
        print("Error: la contraseña no puede estar vacía.")
        return None

    if len(password) < 6:
        print("Error: la contraseña debe tener al menos 6 caracteres.")
        return None

    if confirm and given is None:
        if getpass("Repite la contraseña: ") != password:
            print("Error: las contraseñas no coinciden.")
            return None

    return password


def ask_key_password(keystore_password, given=None, confirm=False):
    # contraseña del alias: si se pulsa ENTER se usa la del KeyStore
    if given is not None:
        key_password = given
    else:
        key_password = getpass("Contraseña del alias (ENTER = la misma que la del KeyStore): ")

    if not key_password:
        return keystore_password

    if len(key_password) < 6:
        print("Error: la contraseña debe tener al menos 6 caracteres.")
        return None

    if confirm and given is None:
        if getpass("Repite la contraseña del alias: ") != key_password:
            print("Error: las contraseñas no coinciden.")
            return None

    return key_password


def ask_alias(given=None, label="Alias"):
    alias = given if given is not None else input(f"{label}: ")
    alias = alias.strip()

    if not alias:
        print("Error: el alias no puede estar vacío.")
        return None

    return alias


def ask_subject_data():
    print("\n=== Datos del titular ===")

    fields = {
        "CN": input("CN (Common Name): ").strip(),
        "OU": input("OU (Organizational Unit): ").strip(),
        "O": input("O (Organization): ").strip(),
        "L": input("L (Locality): ").strip(),
        "ST": input("ST (State/Province): ").strip(),
        "C": input("C (Country): ").strip().upper(),
    }

    for name, value in fields.items():
        if not value:
            print(f"Error: el campo {name} no puede estar vacío.")
            return None

    if len(fields["C"]) != 2:
        print("Error: el campo C debe tener exactamente 2 caracteres.")
        return None

    return fields


def open_store(opts):
    # comprobar que el almacen existe y pedir su contraseña
    # devuelve (ruta, contraseña) o None si no se puede continuar
    path = opt(opts, "keystore")

    if not keystore_exists(path):
        print(f"Error: el KeyStore no existe ({path or KEYSTORE_FILE}). Genera primero un par de claves.")
        return None

    password = ask_password(opt(opts, "storepass"))
    if not password:
        return None

    return path, password


def safe_name(alias):
    # nombre de archivo seguro a partir de un alias
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in alias)


def required_file(opts, *names):
    # nombre de archivo indicado con alguna de las opciones (-file, -infile...) o como argumento suelto
    for name in names + ("archivo",):
        value = opt(opts, name)
        if value:
            return value

    return None


def get_certificate(entry):
    # certificado guardado en una entrada o None si no tiene
    pem = entry.get("certificate")
    return load_certificate_pem(pem) if pem else None


def check_validity(days):
    if days is None:
        return 90

    if days < 1:
        raise ValueError("La validez debe ser de al menos 1 día")

    return days


# ==========================================
# ============== GENKEYPAIR ================
# ==========================================

@safe
def genkeypair(opts=None):
    print("=== Generación de par de claves ===")

    path = opt(opts, "keystore")

    if (opt(opts, "keyalg") or "RSA").upper() != "RSA":
        return fail("solo se admite el algoritmo RSA (-keyalg RSA)")

    key_size = opt(opts, "keysize") or 2048
    if key_size not in KEY_SIZES:
        return fail("tamaño de clave no válido; usa 2048 (por defecto), 3072 o 4096")

    days = check_validity(opt(opts, "validity"))

    # si el almacen es nuevo se pide confirmar la contraseña
    password = ask_password(opt(opts, "storepass"), confirm=not keystore_exists(path))
    if not password:
        return 1

    alias = ask_alias(opt(opts, "alias"))
    if not alias:
        return 1

    # comprobar contraseña y alias antes de pedir mas datos y generar la clave
    if keystore_exists(path) and alias_exists(alias, password, path):
        return fail("el alias ya existe")

    # contraseña propia del alias (ENTER = la misma que la del KeyStore)
    key_password = ask_key_password(password, opt(opts, "keypass"), confirm=True)
    if not key_password:
        return 1

    # el DN se crea antes de generar la clave por si algun dato no es valido
    # (por ejemplo, un CN de mas de 64 caracteres)
    if opt(opts, "dname"):
        subject = parse_dname(opt(opts, "dname"))
    else:
        subject_data = ask_subject_data()
        if not subject_data:
            return 1

        subject = create_subject(
            cn=subject_data["CN"],
            ou=subject_data["OU"],
            o=subject_data["O"],
            l=subject_data["L"],
            st=subject_data["ST"],
            c=subject_data["C"]
        )

    private_key = generate_rsa_key(key_size)

    # como keytool, se crea tambien un certificado AUTOFIRMADO (nadie lo ha validado)
    certificate = create_self_signed_certificate(private_key, subject, days)

    save_key(alias, private_key, subject, password, key_password, certificate, path)

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
    kind = entry_type(entry)
    certificate = get_certificate(entry)

    print(f"{alias}, {entry.get('created', 'fecha desconocida')}, {kind}")

    if kind == SECRET_KEY_ENTRY:
        print(f"  Clave secreta {entry.get('algorithm')} de {entry.get('key_size')} bits (no se muestra)")
        return

    if certificate:
        print(f"  Huella del certificado (SHA-256): {fingerprint_sha256(certificate)}")
    else:
        print("  Sin certificado asociado")

    if verbose:
        if kind == PRIVATE_KEY_ENTRY:
            size = entry.get("key_size")
            print(f"  Clave privada: RSA {size} bits (protegida, no se muestra)" if size
                  else "  Clave privada: protegida, no se muestra")
            if not certificate:
                print(f"  Titular: {entry.get('subject')}")

        if certificate:
            show_certificate_info(certificate, "  ")


@safe
def list_entries(opts=None):
    store = open_store(opts)
    if not store:
        return 1

    path, password = store
    data = load_keystore(password, path)
    alias = opt(opts, "alias")

    if alias is not None:
        if alias not in data:
            return fail("el alias no existe")

        items = [(alias, data[alias])]
    else:
        items = list(data.items())

    print("Tipo de almacén: KeyStore cifrado (PBKDF2 + Fernet)")
    print(f"Archivo: {path or KEYSTORE_FILE}")
    print(f"Número de entradas: {len(items)}")

    for entry_alias, entry in items:
        print()
        print_entry(entry_alias, entry, bool(opt(opts, "v")))

    return 0


# ==========================================
# =============== CERTREQ ==================
# ==========================================

@safe
def certreq(opts=None):
    print("=== Generación de solicitud de firma de certificado (CSR) ===")

    # comprobar antes de pedir datos que el almacen existe
    store = open_store(opts)
    if not store:
        return 1

    path, password = store

    alias = ask_alias(opt(opts, "alias"))
    if not alias:
        return 1

    key_password = ask_key_password(password, opt(opts, "keypass"))
    if not key_password:
        return 1

    print()
    print("Recuperando clave del KeyStore...")

    csr = generate_csr_for_alias(alias, password, key_password, path)
    filepath = save_csr(csr, opt(opts, "file") or safe_name(alias) + ".csr")

    print()
    print("CSR generada correctamente.")
    print("Archivo:", filepath)
    return 0


@safe
def printcertreq(opts=None):
    filename = required_file(opts, "file")
    if not filename:
        return fail("indica el archivo CSR: -printcertreq -file ARCHIVO.csr")

    csr = verify_csr(input_path(filename))
    show_csr_info(csr)
    return 0


# ==========================================
# ============== EXPORTCERT ================
# ==========================================

@safe
def exportcert(opts=None):
    store = open_store(opts)
    if not store:
        return 1

    path, password = store

    alias = ask_alias(opt(opts, "alias"))
    if not alias:
        return 1

    entry = get_key(alias, password, path)
    certificate = get_certificate(entry)

    if certificate is None:
        return fail("el alias no tiene certificado asociado (solo hay clave privada o clave secreta)")

    filepath = output_path(opt(opts, "file") or safe_name(alias) + ".crt")
    write_certificate(certificate, filepath, bool(opt(opts, "rfc")))

    print(f"Certificado almacenado en el archivo: {filepath}")
    print("Formato:", "PEM (-rfc)" if opt(opts, "rfc") else "DER (binario)")
    print("Solo se exporta el certificado (clave pública); la clave privada no sale del KeyStore.")
    return 0


# ==========================================
# ========= DELETE / CHANGEALIAS ===========
# ==========================================

@safe
def delete(opts=None):
    store = open_store(opts)
    if not store:
        return 1

    path, password = store

    alias = ask_alias(opt(opts, "alias"))
    if not alias:
        return 1

    delete_entry(alias, password, path)
    print(f"Entrada {alias} eliminada del KeyStore.")
    return 0


@safe
def changealias(opts=None):
    store = open_store(opts)
    if not store:
        return 1

    path, password = store

    alias = ask_alias(opt(opts, "alias"))
    if not alias:
        return 1

    new_alias = ask_alias(opt(opts, "destalias"), "Alias nuevo")
    if not new_alias:
        return 1

    rename_entry(alias, new_alias, password, path)
    print(f"Alias cambiado: {alias} -> {new_alias}")
    return 0


# ==========================================
# ================ PRINTCERT ===============
# ==========================================

@safe
def printcert(opts=None):
    filename = required_file(opts, "file")
    if not filename:
        return fail("indica el archivo del certificado: -printcert -file ARCHIVO.crt")

    show_certificate_info(load_certificate_file(input_path(filename)))
    return 0


@safe
def printcrl(opts=None):
    filename = required_file(opts, "file")
    if not filename:
        return fail("indica el archivo de la CRL: -printcrl -file ARCHIVO.crl")

    show_crl_info(load_crl_file(input_path(filename)))
    return 0


# ==========================================
# ========= STOREPASSWD / KEYPASSWD ========
# ==========================================

def ask_new_password(given, label):
    password = given if given is not None else getpass(f"{label}: ")

    if not password or len(password) < 6:
        print("Error: la contraseña nueva debe tener al menos 6 caracteres.")
        return None

    if given is None and getpass("Repite la contraseña nueva: ") != password:
        print("Error: las contraseñas no coinciden.")
        return None

    return password


@safe
def storepasswd(opts=None):
    store = open_store(opts)
    if not store:
        return 1

    path, password = store

    new_password = ask_new_password(opt(opts, "new"), "Nueva contraseña del KeyStore")
    if not new_password:
        return 1

    change_store_password(password, new_password, path)
    print("Contraseña del KeyStore cambiada. El archivo se ha cifrado de nuevo con la contraseña nueva.")
    return 0


@safe
def keypasswd(opts=None):
    store = open_store(opts)
    if not store:
        return 1

    path, password = store

    alias = ask_alias(opt(opts, "alias"))
    if not alias:
        return 1

    entry = get_key(alias, password, path)

    if entry_type(entry) != PRIVATE_KEY_ENTRY:
        return fail("solo se puede cambiar la contraseña de entradas con clave privada")

    old_key_password = ask_key_password(password, opt(opts, "keypass"))
    if not old_key_password:
        return 1

    new_key_password = ask_new_password(opt(opts, "new"), "Nueva contraseña del alias")
    if not new_key_password:
        return 1

    # descifrar con la contraseña antigua y volver a cifrar con la nueva
    private_key = load_private_key(entry["private_key"], old_key_password)
    entry["private_key"] = private_key_to_pem(private_key, new_key_password)

    replace_entry(alias, entry, password, path)
    print(f"Contraseña del alias {alias} cambiada.")
    return 0


# ==========================================
# ============== IMPORTCERT ================
# ==========================================

def issuer_in_store(certificate, data, skip_alias):
    # buscar en el almacen un certificado que haya firmado a este (cadena de certificados)
    for alias, entry in data.items():
        if alias == skip_alias or not entry.get("certificate"):
            continue

        issuer = load_certificate_pem(entry["certificate"])
        if issuer.subject == certificate.issuer and is_signed_by(certificate, issuer):
            return True

    return False


@safe
def importcert(opts=None):
    filename = required_file(opts, "file")
    if not filename:
        return fail("indica el certificado a importar: -importcert -file ARCHIVO.crt")

    certificate = load_certificate_file(input_path(filename))
    path = opt(opts, "keystore")
    exists = keystore_exists(path)

    password = ask_password(opt(opts, "storepass"), confirm=not exists)
    if not password:
        return 1

    alias = ask_alias(opt(opts, "alias"))
    if not alias:
        return 1

    data = load_keystore(password, path) if exists else {}

    if alias in data:
        # el alias ya tiene clave privada: el certificado es la respuesta de la CA a nuestra csr
        entry = data[alias]

        if entry_type(entry) != PRIVATE_KEY_ENTRY:
            return fail("el alias ya existe y no es un par de claves")

        if "public_key" not in entry:
            return fail("entrada antigua sin clave pública guardada; vuelve a generar el par de claves")

        if not same_public_key(certificate, entry["public_key"]):
            return fail("la clave pública del certificado no coincide con la del alias")

        if not is_self_signed(certificate) and not issuer_in_store(certificate, data, alias):
            return fail("no se puede establecer la cadena: falta en el KeyStore el certificado del emisor")

        entry["certificate"] = certificate_to_pem(certificate)
        save_keystore(data, password, path)
        print(f"Respuesta de certificado instalada en el alias {alias}.")
        return 0

    # alias nuevo: se guarda como certificado de confianza (sin clave privada)
    print("Certificado a importar:")
    show_certificate_info(certificate, "  ")

    if not opt(opts, "noprompt"):
        answer = input("¿Confiar en este certificado? [no]: ").strip().lower()
        if answer not in YES:
            print("El certificado no se ha añadido.")
            return 1

    data[alias] = {
        "type": TRUSTED_CERT_ENTRY,
        "certificate": certificate_to_pem(certificate),
        "subject": certificate.subject.rfc4514_string(),
        "created": now_text(),
    }
    save_keystore(data, password, path)
    print(f"Certificado añadido al KeyStore como certificado de confianza ({alias}).")
    return 0


# ==========================================
# ================ GENCERT =================
# ==========================================

@safe
def gencert(opts=None):
    infile = required_file(opts, "infile")
    if not infile:
        return fail("indica la CSR con -infile ARCHIVO.csr")

    days = check_validity(opt(opts, "validity"))

    store = open_store(opts)
    if not store:
        return 1

    path, password = store

    alias = ask_alias(opt(opts, "alias"), "Alias del emisor")
    if not alias:
        return 1

    entry = get_key(alias, password, path)
    issuer_certificate = get_certificate(entry)

    if entry_type(entry) != PRIVATE_KEY_ENTRY or issuer_certificate is None:
        return fail("el alias del emisor necesita clave privada y certificado")

    now = datetime.datetime.now(datetime.timezone.utc)
    if not issuer_certificate.not_valid_before_utc <= now <= issuer_certificate.not_valid_after_utc:
        return fail("el certificado del emisor está caducado o todavía no es válido")

    key_password = ask_key_password(password, opt(opts, "keypass"))
    if not key_password:
        return 1

    # la csr debe tener la firma valida: demuestra que quien la envia posee la clave privada
    csr = verify_csr(input_path(infile))
    issuer_key = load_private_key(entry["private_key"], key_password)

    certificate = issue_certificate(csr, issuer_key, issuer_certificate, days)

    base = os.path.splitext(os.path.basename(infile))[0]
    filepath = output_path(opt(opts, "outfile") or safe_name(base) + ".crt")
    write_certificate(certificate, filepath, bool(opt(opts, "rfc")))

    print("Certificado emitido correctamente.")
    print(f"Titular: {certificate.subject.rfc4514_string()}")
    print(f"Emisor: {certificate.issuer.rfc4514_string()}")
    print(f"Válido durante {days} días.")
    print(f"Archivo: {filepath}")
    print("Aviso: el emisor es un alias de este KeyStore, no una CA real; solo sirve para practicar.")
    return 0


# ==========================================
# ============== GENSECKEY =================
# ==========================================

@safe
def genseckey(opts=None):
    path = opt(opts, "keystore")

    if (opt(opts, "keyalg") or "AES").upper() != "AES":
        return fail("solo se admite el algoritmo AES (-keyalg AES)")

    key_size = opt(opts, "keysize") or 256
    if key_size not in AES_SIZES:
        return fail("tamaño no válido para AES; usa 128, 192 o 256 (por defecto 256)")

    password = ask_password(opt(opts, "storepass"), confirm=not keystore_exists(path))
    if not password:
        return 1

    alias = ask_alias(opt(opts, "alias"))
    if not alias:
        return 1

    # clave aleatoria generada con el generador seguro del sistema
    secret = secrets.token_bytes(key_size // 8)

    # la clave queda dentro del KeyStore, que ya esta cifrado con la contraseña del almacen
    add_entry(alias, {
        "type": SECRET_KEY_ENTRY,
        "algorithm": "AES",
        "key_size": key_size,
        "secret_key": base64.b64encode(secret).decode("ascii"),
        "created": now_text(),
    }, password, path)

    print(f"Clave secreta AES de {key_size} bits guardada con el alias {alias}.")
    print("La clave no se muestra. Está protegida por la contraseña del KeyStore.")
    return 0


# ==========================================
# ============ IMPORTKEYSTORE ==============
# ==========================================

@safe
def importkeystore(opts=None):
    src_path = opt(opts, "srckeystore")
    dest_path = opt(opts, "destkeystore")

    if not src_path:
        return fail("indica el KeyStore de origen con -srckeystore ARCHIVO")

    if not keystore_exists(src_path):
        return fail(f"el KeyStore de origen no existe ({src_path})")

    if os.path.abspath(src_path) == os.path.abspath(dest_path or KEYSTORE_FILE):
        return fail("el origen y el destino son el mismo archivo")

    src_password = ask_password(opt(opts, "srcstorepass"), label="Contraseña del KeyStore de origen")
    if not src_password:
        return 1

    src_data = load_keystore(src_password, src_path)

    dest_exists = keystore_exists(dest_path)
    dest_password = ask_password(
        opt(opts, "deststorepass"), confirm=not dest_exists,
        label="Contraseña del KeyStore de destino"
    )
    if not dest_password:
        return 1

    dest_data = load_keystore(dest_password, dest_path) if dest_exists else {}

    src_alias = opt(opts, "srcalias")
    if src_alias is not None and src_alias not in src_data:
        return fail("el alias de origen no existe")

    aliases = [src_alias] if src_alias is not None else list(src_data)
    imported = 0

    for alias in aliases:
        if alias in dest_data:
            print(f"Aviso: el alias {alias} ya existe en el destino; no se importa.")
        else:
            # las claves privadas se copian tal cual: siguen cifradas con su contraseña de alias
            dest_data[alias] = src_data[alias]
            imported += 1

    if imported:
        save_keystore(dest_data, dest_password, dest_path)

    print(f"Entradas importadas: {imported}")
    return 0


# ==========================================
# ========== SHOWINFO / VERSION ============
# ==========================================

def showinfo(opts=None):
    print(f"Simulador: mykeytool {VERSION}")
    print("Cifrado del KeyStore: Fernet (AES-128-CBC + HMAC-SHA256, con autenticación)")
    print(f"Derivación de clave: PBKDF2-HMAC-SHA256, {ITERATIONS} iteraciones, salt aleatorio de 16 bytes")
    print("Claves privadas de los alias: PKCS#8 cifradas con la contraseña del alias")
    print(f"Claves asimétricas: RSA {', '.join(str(s) for s in KEY_SIZES)} bits (por defecto 2048); firmas SHA-256")
    print(f"Claves simétricas: AES {', '.join(str(s) for s in AES_SIZES)} bits (por defecto 256)")
    print(f"Python: {sys.version.split()[0]}")
    print(f"OpenSSL de Python: {ssl.OPENSSL_VERSION}")
    print(f"TLS 1.3 disponible: {'sí' if ssl.HAS_TLSv1_3 else 'no'}")
    return 0


def version(opts=None):
    print(f"mykeytool {VERSION} (simulador de Java Keytool en Python)")
    return 0
