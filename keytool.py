# programa principal: simulacion de Java Keytool en Python
# lee los argumentos de la terminal (argparse), muestra la ayuda y llama al comando elegido
# los comandos se pueden escribir como en keytool (-genkeypair) o con doble guion (--genkeypair)

import argparse
import sys

# importar el modulo que contiene las funciones de cada comando
import commands


# ==========================================
# ================ AYUDA ===================
# ==========================================

# diccionario con las opciones que puede utilizar cada comando
# cada opcion tiene un nombre para el valor que recibe y una descripcion
# se reutiliza para mostrar la ayuda general de cada comando
OPTION_HELP = {
    "-alias": ("ALIAS", "nombre que identifica la entrada en el KeyStore"),
    "-keystore": ("ARCHIVO", "KeyStore a usar (por defecto data/keystore.enc)"),
    "-storepass": ("CLAVE", "contraseña del KeyStore (si se omite, se pide sin mostrarla)"),
    "-keypass": ("CLAVE", "contraseña del alias (si se omite, se pide; ENTER = la del KeyStore)"),
    "-file": ("ARCHIVO", "archivo de entrada o de salida (un nombre sin carpeta se guarda/busca en data/)"),
    "-infile": ("ARCHIVO", "archivo de entrada (CSR)"),
    "-outfile": ("ARCHIVO", "archivo de salida (certificado)"),
    "-keyalg": ("ALGORITMO", "algoritmo de la clave (RSA en pares de claves, AES en claves secretas)"),
    "-keysize": ("BITS", "tamaño de la clave (RSA: 2048, 3072 o 4096; AES: 128, 192 o 256)"),
    "-validity": ("DIAS", "días de validez del certificado (por defecto 90)"),
    "-dname": ("DN", 'datos del titular, p. ej. "CN=Ana, OU=DAM, O=CETI, L=Badalona, ST=Barcelona, C=ES" (si se omite, se piden)'),
    "-rfc": ("", "escribir el certificado en PEM (texto) en lugar de DER (binario)"),
    "-noprompt": ("", "no pedir confirmación"),
    "-v": ("", "mostrar información detallada"),
    "-new": ("CLAVE", "contraseña nueva"),
    "-destalias": ("ALIAS", "alias nuevo"),
    "-srckeystore": ("ARCHIVO", "KeyStore de origen"),
    "-destkeystore": ("ARCHIVO", "KeyStore de destino (por defecto data/keystore.enc)"),
    "-srcstorepass": ("CLAVE", "contraseña del KeyStore de origen"),
    "-deststorepass": ("CLAVE", "contraseña del KeyStore de destino"),
    "-srcalias": ("ALIAS", "importar solo este alias (si se omite, todos)"),
}


# diccionario que define los comandos disponibles en el simulador
# cada comando tiene su grupo, descripcion, opciones admitidas y ejemplo de uso
COMMANDS = {
    "genkeypair": {
        "group": "Claves y KeyStore",
        "short": "Genera un par de claves RSA y un certificado autofirmado",
        "long": "Pide (o lee de las opciones) la contraseña del KeyStore, el alias y los datos del titular. "
                "Genera un par RSA y un certificado AUTOFIRMADO (sin validar por ninguna CA). "
                "La clave privada se guarda cifrada en el KeyStore. También se admite --genkey.",
        "options": ["-alias", "-keyalg", "-keysize", "-dname", "-validity", "-keystore", "-storepass", "-keypass"],
        "example": "python keytool.py -genkeypair -alias prueba -keyalg RSA -keysize 2048",
    },
    "genseckey": {
        "group": "Claves y KeyStore",
        "short": "Genera una clave secreta (AES)",
        "long": "Genera una clave simétrica AES aleatoria y la guarda en el KeyStore. La clave nunca se muestra.",
        "options": ["-alias", "-keyalg", "-keysize", "-keystore", "-storepass"],
        "example": "python keytool.py -genseckey -alias miaes -keyalg AES -keysize 256",
    },
    "list": {
        "group": "Claves y KeyStore",
        "short": "Muestra las entradas del KeyStore",
        "long": "Lista alias, fecha, tipo y huella SHA-256 del certificado. Nunca muestra claves privadas ni secretas.",
        "options": ["-alias", "-v", "-keystore", "-storepass"],
        "example": "python keytool.py -list -v",
    },
    "delete": {
        "group": "Claves y KeyStore",
        "short": "Elimina una entrada del KeyStore",
        "long": "Borra el alias indicado. El resto de entradas no se modifica.",
        "options": ["-alias", "-keystore", "-storepass"],
        "example": "python keytool.py -delete -alias prueba",
    },
    "changealias": {
        "group": "Claves y KeyStore",
        "short": "Cambia el alias de una entrada",
        "long": "Cambia el nombre de la entrada sin perder su clave ni su certificado.",
        "options": ["-alias", "-destalias", "-keystore", "-storepass"],
        "example": "python keytool.py -changealias -alias prueba -destalias final",
    },
    "storepasswd": {
        "group": "Claves y KeyStore",
        "short": "Cambia la contraseña del KeyStore",
        "long": "Descifra el almacén con la contraseña actual y lo vuelve a cifrar con la nueva (con salt nuevo).",
        "options": ["-new", "-keystore", "-storepass"],
        "example": "python keytool.py -storepasswd",
    },
    "keypasswd": {
        "group": "Claves y KeyStore",
        "short": "Cambia la contraseña de la clave de un alias",
        "long": "Cambia la contraseña con la que está cifrada la clave privada de un alias.",
        "options": ["-alias", "-keypass", "-new", "-keystore", "-storepass"],
        "example": "python keytool.py -keypasswd -alias prueba",
    },
    "importkeystore": {
        "group": "Claves y KeyStore",
        "short": "Importa entradas de otro KeyStore",
        "long": "Copia las entradas de otro KeyStore de este simulador. Si un alias ya existe en el destino, no se sobrescribe.",
        "options": ["-srckeystore", "-destkeystore", "-srcstorepass", "-deststorepass", "-srcalias"],
        "example": "python keytool.py -importkeystore -srckeystore otro.enc",
    },
    "certreq": {
        "group": "Certificados y CSR",
        "short": "Genera una solicitud de certificado (CSR)",
        "long": "Crea una CSR en formato PEM firmada con la clave privada del alias. Una CSR NO es un certificado: "
                "hay que enviarla a una CA para que la firme.",
        "options": ["-alias", "-file", "-keypass", "-keystore", "-storepass"],
        "example": "python keytool.py -certreq -alias prueba -file prueba.csr",
    },
    "printcertreq": {
        "group": "Certificados y CSR",
        "short": "Comprueba y muestra una CSR",
        "long": "Comprueba que el archivo existe, que es una CSR PEM y que su firma es válida, y muestra los datos del solicitante.",
        "options": ["-file"],
        "example": "python keytool.py -printcertreq -file prueba.csr",
    },
    "gencert": {
        "group": "Certificados y CSR",
        "short": "Genera un certificado a partir de una CSR",
        "long": "Firma una CSR con la clave privada de un alias del KeyStore (que actúa como CA de práctica). "
                "Comprueba antes la firma de la CSR y la validez del certificado del emisor.",
        "options": ["-alias", "-infile", "-outfile", "-validity", "-rfc", "-keypass", "-keystore", "-storepass"],
        "example": "python keytool.py -gencert -alias ca -infile prueba.csr -outfile prueba.crt -rfc",
    },
    "exportcert": {
        "group": "Certificados y CSR",
        "short": "Exporta el certificado de una entrada",
        "long": "Guarda el certificado (solo la clave pública) en un archivo. Por defecto en DER; con -rfc en PEM.",
        "options": ["-alias", "-file", "-rfc", "-keystore", "-storepass"],
        "example": "python keytool.py -exportcert -alias prueba -file prueba.crt -rfc",
    },
    "importcert": {
        "group": "Certificados y CSR",
        "short": "Importa un certificado o la respuesta de una CA",
        "long": "Si el alias ya tiene clave privada, instala el certificado como respuesta a su CSR (comprueba que la clave "
                "pública coincide y que el emisor está en el KeyStore). Si el alias es nuevo, lo guarda como certificado de confianza.",
        "options": ["-alias", "-file", "-noprompt", "-keystore", "-storepass"],
        "example": "python keytool.py -importcert -alias prueba -file prueba.crt",
    },
    "printcert": {
        "group": "Certificados y CSR",
        "short": "Muestra el contenido de un certificado",
        "long": "Lee un certificado PEM o DER y muestra titular, emisor, validez, clave pública y huella. Comprueba la firma si es autofirmado.",
        "options": ["-file"],
        "example": "python keytool.py -printcert -file prueba.crt",
    },
    "printcrl": {
        "group": "Otros",
        "short": "Muestra el contenido de una CRL",
        "long": "Lee una lista de revocación (PEM o DER) y muestra emisor, fechas y certificados revocados. No comprueba su firma.",
        "options": ["-file"],
        "example": "python keytool.py -printcrl -file lista.crl",
    },
    "showinfo": {
        "group": "Otros",
        "short": "Muestra información de seguridad del simulador",
        "long": "Muestra los algoritmos y parámetros que usa el simulador y las versiones de Python y OpenSSL.",
        "options": [],
        "example": "python keytool.py -showinfo",
    },
    "version": {
        "group": "Otros",
        "short": "Muestra la versión del simulador",
        "long": "Muestra la versión de mykeytool.",
        "options": [],
        "example": "python keytool.py -version",
    },
}


# relacionar cada nombre de comando con la funcion que lo ejecuta
# asi main puede encontrar la funcion correcta sin usar muchos if y elif
HANDLERS = {
    "genkeypair": commands.genkeypair,
    "genseckey": commands.genseckey,
    "list": commands.list_entries,
    "delete": commands.delete,
    "changealias": commands.changealias,
    "storepasswd": commands.storepasswd,
    "keypasswd": commands.keypasswd,
    "importkeystore": commands.importkeystore,
    "certreq": commands.certreq,
    "printcertreq": commands.printcertreq,
    "gencert": commands.gencert,
    "exportcert": commands.exportcert,
    "importcert": commands.importcert,
    "printcert": commands.printcert,
    "printcrl": commands.printcrl,
    "showinfo": commands.showinfo,
    "version": commands.version,
}


def print_general_help():
    # mostrar el nombre y la forma general de utilizar el programa
    print("mykeytool: simulador de Java Keytool en Python")
    print()
    print("Uso: python keytool.py -COMANDO [opciones]      (también vale --COMANDO)")
    print("     python keytool.py -COMANDO -help           ayuda de un comando")
    print()

    # obtener los grupos de comandos sin repetirlos
    groups = []
    for spec in COMMANDS.values():
        if spec["group"] not in groups:
            groups.append(spec["group"])

    # recorrer los grupos y mostrar los comandos que pertenecen a cada uno
    for group in groups:
        print(f"{group}:")
        for name, spec in COMMANDS.items():
            if spec["group"] == group:
                text_name = name
                
                # Si es genkeypair, exportcert o importcert, mostramos visualmente el alias histórico
                if name == "genkeypair":
                    text_name = "genkeypair / -genkey"
                elif name == "exportcert":
                    text_name = "exportcert / -export"
                elif name == "importcert":
                    text_name = "importcert / -import"
                    
                print(f"  -{text_name:<25}{spec['short']}")
        print()

    # explicar las formas disponibles de pedir ayuda

    print("Ayuda: -h, -?, -help o --help")
    print()
    print("Si no se indican contraseñas, alias o datos del titular, el programa los asigna como \"Unknown\" automáticamente.")
    print("Los archivos sin carpeta (CSR, certificados) se guardan y buscan en la carpeta data/.")
    print()

    # avisar de un comando de Java Keytool que no se ha implementado
    print("No implementado: -importpass (guardar contraseñas como entradas no se ha incluido en este simulador).")
    print("Diferencias con Java Keytool: ver README.md (apartado Limitaciones).")


def print_command_help(name):
    # recuperar la informacion del comando solicitado
    spec = COMMANDS[name]

    # mostrar su descripcion y la forma de utilizarlo
    print(f"-{name}: {spec['short']}")
    print()
    print(spec["long"])
    print()
    print(f"Uso: python keytool.py -{name} [opciones]")

    # mostrar las opciones que admite este comando
    if spec["options"]:
        print()
        print("Opciones:")
        for option in spec["options"]:
            # obtener el nombre del valor y la explicacion de la opcion
            metavar, text = OPTION_HELP[option]
            print(f"  {(option + ' ' + metavar).strip():<26}{text}")

    # mostrar un ejemplo de uso
    print()
    print("Ejemplo:")
    print(f"  {spec['example']}")


# ==========================================
# ============== ARGUMENTOS ================
# ==========================================

class SpanishParser(argparse.ArgumentParser):
    # argparse muestra los errores en ingles; aqui se muestran en español y sin traza
    def error(self, message):
        # imprimir un mensaje de error en la salida de errores
        print(f"Error: argumentos no validos ({message}).", file=sys.stderr)

        # indicar donde consultar los comandos disponibles
        print("Usa python keytool.py --help para ver los comandos disponibles.", file=sys.stderr)

        # terminar con codigo 2, que indica un error en los argumentos
        sys.exit(2)


def build_parser():
    # crear el analizador de argumentos
    # add_help=False permite controlar la ayuda manualmente
    # allow_abbrev=False evita aceptar opciones incompletas por accidente
    parser = SpanishParser(add_help=False, allow_abbrev=False)

    # registrar las formas de pedir ayuda
    parser.add_argument("-h", "-?", "-help", "--help", dest="help", action="store_true")

    # crear un grupo que impide seleccionar varios comandos a la vez
    group = parser.add_mutually_exclusive_group()

    # registrar los comandos definidos en COMMANDS
    for name in COMMANDS:
        names = [f"-{name}", f"--{name}"]

        # permitir tambien -genkey como alias de -genkeypair
        if name == "genkeypair":
            names += ["-genkey", "--genkey"]

        # permitir tambien -export como alias de -exportcert
        elif name == "exportcert":
            names += ["-export", "--export"]

        # permitir tambien -import como alias de -importcert
        elif name == "importcert":
            names += ["-import", "--import"]

        group.add_argument(*names, dest="command", action="store_const", const=name)

    # registrar las opciones que reciben un valor de texto
    for name in ("alias", "keystore", "file", "infile", "outfile", "keyalg", "dname",
                 "storepass", "keypass", "new", "destalias", "srckeystore", "destkeystore",
                 "srcstorepass", "deststorepass", "srcalias"):
        parser.add_argument(f"-{name}", f"--{name}", dest=name)

    # registrar las opciones que deben recibir un numero entero
    for name in ("keysize", "validity"):
        parser.add_argument(f"-{name}", f"--{name}", dest=name, type=int)

    # registrar las opciones que funcionan como interruptores
    # si aparecen en la terminal, su valor pasa a ser True
    for name in ("rfc", "noprompt"):
        parser.add_argument(f"-{name}", f"--{name}", dest=name, action="store_true")

    # opcion corta para mostrar informacion detallada
    parser.add_argument("-v", dest="v", action="store_true")

    # permitir un argumento de archivo sin nombre de opcion
    # nargs="?" hace que sea opcional y que solo se acepte uno
    parser.add_argument("archivo", nargs="?")

    # devolver el parser preparado
    return parser


def main(argv=None):
    # utilizar los argumentos recibidos o, si no se han pasado,
    # los argumentos escritos por el usuario en la terminal
    argv = sys.argv[1:] if argv is None else argv

    # importpass existe en Java Keytool pero no esta implementado aqui
    # comprobarlo antes de analizar el resto de argumentos
    if "-importpass" in argv or "--importpass" in argv:
        print("Error: -importpass no está implementado en este simulador.")
        return 1

    # analizar los argumentos y guardarlos en el objeto args
    args = build_parser().parse_args(argv)

    # resolver la ayuda antes de ejecutar el comando
    # por ejemplo, -genkeypair --help muestra la ayuda sin generar claves
    if args.help:
        if args.command:
            # si se ha indicado un comando, mostrar solo su ayuda
            print_command_help(args.command)
        else:
            # si no se ha indicado, mostrar la ayuda general
            print_general_help()
        return 0

    # si no se ha elegido ningun comando, mostrar la ayuda general
    if not args.command:
        print_general_help()

        # devolver 0 si no se han escrito argumentos y 1 si faltaba un comando
        return 0 if not argv else 1

    try:
        # buscar la funcion asociada al comando y ejecutarla con sus argumentos
        return HANDLERS[args.command](args)

    except (KeyboardInterrupt, EOFError):
        # controlar la cancelacion con Ctrl+C o el fin inesperado de la entrada
        print("\nOperación cancelada.")
        return 1


# ejecutar main solo cuando este archivo se inicia directamente
# evita que se ejecute automaticamente al importarlo desde otro modulo
if __name__ == "__main__":
    # terminar el programa usando el codigo de salida devuelto por main
    sys.exit(main())