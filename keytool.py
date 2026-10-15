
# simulador de java keytool en python
# permite generar pares de claves rsa y solicitudes csr desde la terminal

# importar argparse para recibir comandos desde la terminal
import argparse

# importar getpass para pedir la contrasena sin mostrarla por pantalla
from getpass import getpass

# importar las funciones para generar claves rsa y crear el dn
from crypto_utils import generate_rsa_key, create_subject

# importar las funciones para guardar y recuperar claves del keystore
from keystore import save_key, get_key

# importar las funciones para generar y guardar solicitudes csr
from csr import generate_csr_for_alias, save_csr


# ==========================================
# ============== GENKEYPAIR ================
# ==========================================

def genkeypair():
    # mostrar el titulo de la operacion
    print("=== Generacion de par de claves ===")

    # pedir la contrasena del keystore sin mostrarla por pantalla
    password = getpass("Contrasena del KeyStore: ")

    # comprobar que la contrasena no este vacia
    if not password:
        print("Error: la contrasena no puede estar vacia.")
        return

    # pedir el alias que identificara las claves guardadas
    alias = input("Alias: ").strip()

    # comprobar que el alias no este vacio
    if not alias:
        print("Error: el alias no puede estar vacio.")
        return

    # pedir los datos del titular que se guardaran en el dn
    print("\n=== Datos del titular ===")

    # solicitar el nombre comun del titular
    cn = input("CN (Common Name): ").strip()

    # solicitar la unidad organizativa
    ou = input("OU (Organizational Unit): ").strip()

    # solicitar el nombre de la organizacion
    o = input("O (Organization): ").strip()

    # solicitar la localidad
    l = input("L (Locality): ").strip()

    # solicitar el estado o provincia
    st = input("ST (State/Province): ").strip()

    # solicitar el pais y convertirlo a mayusculas
    c = input("C (Country, 2 letras): ").strip().upper()

    # guardar todos los campos en una lista para comprobarlos
    fields = [cn, ou, o, l, st, c]

    # comprobar que todos los campos del titular tengan un valor
    if any(not value for value in fields):
        print("Error: todos los campos del titular son obligatorios.")
        return

    # comprobar que el pais tenga exactamente dos letras ascii
    # por ejemplo, es para espana o fr para francia
    if len(c) != 2 or not c.isalpha() or not c.isascii():
        print("Error: C debe contener dos letras ASCII.")
        return

    try:
        # generar una clave privada rsa de 2048 bits
        private_key = generate_rsa_key()

        # crear el dn con los datos introducidos por el usuario
        subject = create_subject(cn, ou, o, l, st, c)

        # guardar la clave privada y los datos del titular
        # el contenido del keystore se guarda cifrado con la contrasena
        save_key(alias, private_key, subject, password)

        # mostrar un mensaje de confirmacion y los datos principales
        print("\nPar de claves generado y guardado correctamente.")
        print("Alias:", alias)
        print("Tamano RSA:", private_key.key_size, "bits")
        print("DN:", subject.rfc4514_string())

    # controlar errores relacionados con los datos o los archivos
    except (ValueError, OSError) as error:
        print("Error:", error)


# ==========================================
# ================ CERTREQ =================
# ==========================================

def certreq():
    # mostrar el titulo de la operacion
    print("=== Generacion de solicitud CSR ===")

    # pedir la contrasena del keystore sin mostrarla por pantalla
    password = getpass("Contrasena del KeyStore: ")

    # comprobar que la contrasena no este vacia
    if not password:
        print("Error: la contrasena no puede estar vacia.")
        return

    # pedir el alias de la clave que se utilizara para generar la csr
    alias = input("Alias de la clave: ").strip()

    # comprobar que el alias no este vacio
    if not alias:
        print("Error: el alias no puede estar vacio.")
        return

    try:
        # comprobar que la clave se puede recuperar del keystore
        # tambien permite comprobar la contrasena introducida
        get_key(alias, password)

        # generar la solicitud csr con la clave privada y el dn guardados
        csr = generate_csr_for_alias(alias, password)

        # guardar la solicitud csr en formato pem
        # utilizar el alias como nombre del archivo
        filepath = save_csr(csr, alias + ".csr")

        # mostrar la confirmacion y la ruta del archivo generado
        print("\nCSR generada correctamente.")
        print("Archivo:", filepath)
        print("Formato: PEM")

    # controlar errores relacionados con la clave o los archivos
    except (ValueError, OSError) as error:
        print("Error:", error)


# ==========================================
# ================= MAIN ===================
# ==========================================

def main():
    # crear el analizador de argumentos de la terminal
    # permite ejecutar el programa utilizando diferentes comandos
    parser = argparse.ArgumentParser(
        description="Simulacion de Java Keytool en Python"
    )

    # crear un grupo de comandos excluyentes
    # permite utilizar un comando cada vez
    commands = parser.add_mutually_exclusive_group()

    # anadir el comando para generar un par de claves
    commands.add_argument(
        "--genkeypair",
        action="store_true",
        help="Genera y guarda un par de claves RSA de 2048 bits"
    )

    # anadir el comando para generar una solicitud csr
    commands.add_argument(
        "--certreq",
        action="store_true",
        help="Genera una solicitud CSR en formato PEM"
    )

    # recuperar los argumentos introducidos al ejecutar el programa
    args = parser.parse_args()

    # comprobar si el usuario ha elegido generar un par de claves
    if args.genkeypair:
        genkeypair()

    # comprobar si el usuario ha elegido generar una solicitud csr
    elif args.certreq:
        certreq()

    # si no se introduce ningun comando, mostrar la ayuda
    else:
        parser.print_help()


# comprobar si el archivo se esta ejecutando directamente
# si se importa desde otro archivo, no se ejecuta main automaticamente
if __name__ == "__main__":
    # iniciar el programa
    main()