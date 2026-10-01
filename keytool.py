import argparse

def main():

    # Configuracion de argumentos y del comando --help / -h
    parser = argparse.ArgumentParser(
        description="Simulación de Java Keytool en Python"
    )

    parser.add_argument(
        "--genkeypair",
        action="store_true",
        help="Genera un par de claves RSA de 2048 bits"
    )

    parser.add_argument(
        "--certreq",
        action="store_true",
        help="Genera una solicitud de firma de certificado (CSR)"
    )

    # Configuración de la funcionalidad de los comandos
    args = parser.parse_args()
    
    if args.genkeypair:
        print("Comando --genkeypair seleccionado.") # Mensaje temporal

    elif args.certreq:
        print("Comando --certreq seleccionado.") # Mensaje temporal


if __name__ == "__main__":
    main()