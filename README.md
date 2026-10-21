# Sprint1 - Python Keytool

## 1. Descripción del proyecto

Este proyecto consiste en desarrollar un simulador de **Java Keytool utilizando Python**. Su objetivo es reproducir algunas de las funcionalidades principales de la herramienta original para gestionar claves criptográficas, certificados digitales y solicitudes de certificados.

La aplicación funciona desde la terminal y permite trabajar con un KeyStore para guardar y gestionar información criptográfica.

El proyecto utiliza la biblioteca `cryptography` para realizar las operaciones criptográficas necesarias.

## 2. Funcionalidades

Las principales funcionalidades del proyecto son:

- Generación de pares de claves criptográficas.
- Generación de solicitudes de certificados (CSR).
- Generación e importación de certificados.
- Consulta de certificados y solicitudes.
- Listado de entradas almacenadas en el KeyStore.
- Eliminación y cambio de alias.
- Cambio de contraseñas.
- Generación de claves secretas.
- Importación de KeyStores.
- Verificación de solicitudes CSR.
- Consulta de ayuda, información y versión del programa.

## 3. Tecnologías utilizadas

- **Python:** lenguaje de programación.
- **cryptography:** biblioteca para operaciones criptográficas.
- **argparse:** procesamiento de argumentos de la línea de comandos.
- **Git y GitHub:** control de versiones y almacenamiento del código.

## 4. Estructura del proyecto

```text
Sprint1-Python-Keytool/
│
├── data/
│   ├── keystore.enc
│   ├── cliente.crt
│   ├── cliente.csr
│   ├── num.crt
│   ├── num.csr
│   └── ...
│
│
├── certificates.py
├── commands.py
├── crypto_utils.py
├── csr.py
├── keystore.py
├── keytool.py
├── main.py
├── verify_csr.py
├── requirements.txt
├── comandos de prueba.txt
├── README.md
└── .gitignore
```

### Archivos principales

- `keytool.py`: permite ejecutar los comandos del simulador.
- `main.py`: gestiona la ejecución principal de la aplicación.
- `commands.py`: contiene la implementación de los comandos disponibles.
- `crypto_utils.py`: incluye funciones auxiliares para operaciones criptográficas.
- `keystore.py`: gestiona el KeyStore.
- `csr.py`: contiene funciones relacionadas con las solicitudes de certificados.
- `certificates.py`: gestiona operaciones relacionadas con certificados.
- `verify_csr.py`: permite verificar solicitudes CSR.
- `requirements.txt`: contiene las dependencias necesarias para ejecutar el proyecto.
- `data/`: almacena el KeyStore y los archivos de certificados y solicitudes utilizados.

## 5. Instalación y configuración

### Requisitos previos

- Tener Python instalado.
- Disponer de una terminal, como PowerShell en Windows.
- Instalar las dependencias del proyecto.

### Paso 1. Acceder a la carpeta del proyecto

```powershell
cd "ruta\Sprint1-Python-Keytool"
```

### Paso 2. Instalar las dependencias

```powershell
python -m pip install -r requirements.txt
```

Si es necesario, se puede instalar la biblioteca principal manualmente:

```powershell
python -m pip install cryptography
```

### Paso 3. Consultar la ayuda

```powershell
python keytool.py --help
```

Este comando muestra la ayuda y los argumentos disponibles en el simulador.

## 6. Ejemplos de uso

Los siguientes ejemplos muestran cómo ejecutar las operaciones principales desde la terminal.

### 6.1. Ayuda y ejecución

Consultar los comandos disponibles:

```powershell
python keytool.py --help
```

Iniciar el menú interactivo:

```powershell
python keytool.py
```

Consultar la versión:

```powershell
python keytool.py -version
```

Consultar información general:

```powershell
python keytool.py -showinfo
```

### 6.2. Generación de claves

Generar un par de claves:

```powershell
python keytool.py --genkeypair
```

También se puede utilizar el alias alternativo:

```powershell
python keytool.py --genkey
```

Generar una clave secreta:

```powershell
python keytool.py -genseckey
```

Estas operaciones pueden solicitar datos como el alias, la contraseña o la información necesaria para crear la entrada.

### 6.3. Gestión del KeyStore

Mostrar las entradas almacenadas:

```powershell
python keytool.py -list
```

Cambiar el alias de una entrada:

```powershell
python keytool.py -changealias
```

Eliminar una entrada:

```powershell
python keytool.py -delete
```

Cambiar la contraseña de una clave:

```powershell
python keytool.py -keypasswd
```

Cambiar la contraseña del KeyStore:

```powershell
python keytool.py -storepasswd
```

Exportar un certificado:

```powershell
python keytool.py -exportcert
```

Importar un certificado:

```powershell
python keytool.py -importcert -file data/ejem.crt
```

Importar información desde otro KeyStore:

```powershell
python keytool.py -importkeystore -srckeystore "data/keystore.enc"
```

También se puede indicar el KeyStore de destino:

```powershell
python keytool.py -importkeystore -srckeystore "data/keystore.enc" -destkeystore "keystore.enc"
```

Las operaciones de gestión pueden solicitar parámetros adicionales o depender de que exista una entrada previa. Las rutas deben coincidir con los archivos disponibles en el proyecto.

### 6.4. Solicitudes de certificados (CSR)

Generar una solicitud de certificado:

```powershell
python keytool.py --certreq
```

Mostrar la información de una solicitud:

```powershell
python keytool.py -printcertreq -file data/ejem.csr
```

Verificar una solicitud CSR:

```powershell
python verify_csr.py data/ejem.csr
```

Para trabajar con otra solicitud, se debe sustituir `data/ejem.csr` por la ruta del archivo correspondiente.

### 6.5. Generación de certificados

Generar un certificado a partir de una solicitud CSR:

```powershell
python keytool.py -gencert -infile data/ejem.csr -outfile data/ejem.crt
```

También se puede indicar otra solicitud:

```powershell
python keytool.py --gencert -infile ejem.csr
```

La operación puede necesitar información adicional, como un certificado emisor y su clave privada, según la implementación del simulador.

### 6.6. Consulta de certificados

Mostrar la información de un certificado:

```powershell
python keytool.py -printcert -file data/ejem.crt
```

El archivo indicado debe existir y contener un certificado que el simulador pueda interpretar.

## 7. Flujo de trabajo de ejemplo

A continuación, se muestra un ejemplo de flujo de trabajo para generar claves, crear una solicitud CSR y obtener un certificado.

**Paso 1. Generar el par de claves**

```powershell
python keytool.py --genkeypair
```

**Paso 2. Crear la solicitud CSR**

```powershell
python keytool.py --certreq
```

**Paso 3. Verificar la solicitud**

```powershell
python verify_csr.py data/ejem.csr
```

**Paso 4. Generar el certificado**

```powershell
python keytool.py -gencert -infile data/ejem.csr -outfile data/ejem.crt
```

**Paso 5. Consultar el certificado**

```powershell
python keytool.py -printcert -file data/ejem.crt
```

**Paso 6. Consultar el KeyStore**

```powershell
python keytool.py -list
```

Los nombres `ejem.csr` y `ejem.crt` son ejemplos y deben coincidir con los archivos generados durante la ejecución. La generación del certificado puede requerir un certificado emisor y una clave privada, según cómo esté implementado el simulador.

## 8. Seguridad y almacenamiento

El proyecto utiliza archivos para almacenar el KeyStore y los datos relacionados con claves y certificados.

- `keystore.enc`: archivo destinado al almacenamiento cifrado del KeyStore.
- `.csr`: archivos que contienen solicitudes de certificados.
- `.crt`: archivos que contienen certificados.

Se recomienda no publicar contraseñas ni claves privadas, evitar subir datos sensibles al repositorio y utilizar datos de prueba durante el desarrollo.

La extensión `.enc` por sí sola no garantiza que el contenido esté cifrado correctamente; esto depende de la implementación utilizada.

## 9. Limitaciones

Este proyecto es un simulador educativo desarrollado en Python y no pretende sustituir a la herramienta oficial Java Keytool.

Aunque reproduce operaciones habituales de gestión de claves y certificados, puede presentar diferencias respecto a la herramienta original en los argumentos admitidos, los formatos de almacenamiento y las validaciones.

## 10. Autoría

Proyecto desarrollado como actividad práctica del módulo de criptografía.

**Objetivo:** comprender el funcionamiento de una herramienta de gestión de claves y certificados mediante la implementación de operaciones criptográficas en Python.