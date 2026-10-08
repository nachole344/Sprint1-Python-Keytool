# Simulacion de Java Keytool en Python

## 1. Descripcion del proyecto

Este proyecto consiste en el desarrollo de una aplicacion de linea de comandos (CLI) en Python que simula algunas de las funcionalidades principales de la herramienta `keytool` de Java.

La aplicacion permite generar pares de claves RSA, almacenarlos de forma segura en un KeyStore cifrado y generar solicitudes de firma de certificados (CSR).

El proyecto ha sido desarrollado como practica de programacion y criptografia utilizando Python y la libreria `cryptography`.

---

## 2. Integrantes

* Ignacio Andrés Leal Escarate
* Nuria Font Sanchez

---

## 3. Objetivos

Los principales objetivos del proyecto son:

* Crear una aplicacion CLI utilizando Python.
* Utilizar `argparse` para gestionar los comandos.
* Generar pares de claves RSA de 2048 bits.
* Crear y gestionar un KeyStore.
* Proteger el contenido del KeyStore mediante cifrado.
* Guardar las claves de forma persistente.
* Generar solicitudes CSR en formato PEM.
* Recuperar claves mediante un alias.
* Gestionar errores y excepciones.
* Realizar pruebas de funcionamiento.
* Documentar el proyecto y su funcionamiento.

---

## 4. Tecnologias utilizadas

* Python 3
* `cryptography`
* `argparse`
* `getpass`
* JSON
* Git
* GitHub

### Algoritmos y mecanismos utilizados

* RSA 2048 bits
* SHA-256
* PBKDF2
* Fernet
* CSR
* Formato PEM

---

## 5. Estructura del proyecto

```text
Sprint1-Python-Keytool/
│
├── keytool.py
├── keystore.py
├── csr.py
├── crypto_utils.py
├── verify_csr.py
├── test.py
├── README.md
│
└── data/
    ├── keystore.enc
    └── pepe.csr
```

### Descripcion de los archivos

#### `keytool.py`

Es el archivo principal de la aplicacion.

Se encarga de interpretar los comandos introducidos desde la terminal mediante `argparse`.

Actualmente incluye:

* `--help`
* `--genkeypair`
* `--certreq`
* `--list`

#### `keystore.py`

Gestiona el almacenamiento de las claves.

Sus funciones principales son:

* Crear el directorio `data`.
* Derivar una clave mediante PBKDF2.
* Guardar el KeyStore.
* Cargar el KeyStore.
* Guardar claves mediante un alias.
* Comprobar si existe un alias.
* Obtener una clave almacenada.
* Listar los aliases.

#### `crypto_utils.py`

Contiene las funciones relacionadas con la generacion de claves RSA.

La clave generada tiene un tamaño de 2048 bits.

#### `csr.py`

Gestiona la creacion de los datos del titular y la generacion de solicitudes CSR.

Tambien permite guardar la CSR en formato PEM.

#### `verify_csr.py`

Permite comprobar que una CSR existe, que tiene un formato valido y que su firma es valida.

#### `test.py`

Archivo utilizado para realizar pruebas de las principales funcionalidades del proyecto.

---

# 6. Instalacion

## Requisitos

Es necesario tener instalado:

* Python 3
* pip

Para comprobar la version de Python:

```bash
python --version
```

Tambien se puede utilizar:

```bash
python3 --version
```

---

## Instalacion de la dependencia

La aplicacion utiliza la libreria `cryptography`.

Instalarla con:

```bash
pip install cryptography
```

Si se utiliza un entorno virtual:

```bash
python -m venv venv
```

Activar el entorno virtual en Windows:

```powershell
venv\Scripts\activate
```

Despues instalar la dependencia:

```bash
pip install cryptography
```

---

# 7. Uso de la aplicacion

El programa se ejecuta desde la terminal mediante `keytool.py`.

## 7.1 Mostrar ayuda

Para mostrar los comandos disponibles:

```bash
python keytool.py --help
```

La aplicacion muestra la ayuda proporcionada por `argparse`, incluyendo los comandos disponibles y su descripcion.

### Ejemplo

```text
usage: keytool.py [-h] [--genkeypair | --certreq | --list]

Simulacion de Java Keytool en Python

options:
  -h, --help    show this help message and exit
  --genkeypair  Genera un par de claves RSA de 2048 bits
  --certreq     Genera una solicitud de firma de certificado CSR
  --list        Muestra los aliases del KeyStore
```

---

# 8. Generacion de un par de claves

Para generar una nueva clave:

```bash
python keytool.py --genkeypair
```

El programa solicita:

1. Contraseña del KeyStore.
2. Alias.
3. Common Name (CN).
4. Organizational Unit (OU).
5. Organization (O).
6. Locality (L).
7. State/Province (ST).
8. Country (C).

### Ejemplo

```text
=== Generacion de par de claves ===

Contraseña del KeyStore:
Alias: pepe
CN (Common Name): PEPE
OU (Organizational Unit): DAM
O (Organization): MONLAU
L (Locality): BARCELONA
ST (State/Province): BARCELONA
C (Country): ES

Generando clave RSA...

Par de claves RSA generado correctamente.
Alias: pepe
Tamaño de clave: 2048 bits
DN: C=ES,ST=BARCELONA,L=BARCELONA,O=MONLAU,OU=DAM,CN=PEPE
Clave guardada en el KeyStore.
```

La clave privada se almacena dentro del KeyStore cifrado.

---

# 9. KeyStore

El KeyStore permite almacenar las claves de forma persistente.

El archivo se encuentra en:

```text
data/keystore.enc
```

El contenido del KeyStore no se guarda directamente como texto plano.

El proceso utilizado es:

```text
Contraseña
    ↓
PBKDF2
    ↓
Clave derivada
    ↓
Fernet
    ↓
Datos cifrados
    ↓
keystore.enc
```

Para derivar la clave se utiliza:

* SHA-256
* PBKDF2
* Salt aleatorio
* 600000 iteraciones

El contenido almacenado incluye los aliases y las claves privadas correspondientes.

---

# 10. Generacion de una CSR

Para generar una solicitud de firma de certificado:

```bash
python keytool.py --certreq
```

El programa solicita:

* Contraseña del KeyStore.
* Alias.
* Datos del titular.

La aplicacion recupera la clave privada asociada al alias y genera una CSR.

### Ejemplo

```text
=== Generacion de solicitud CSR ===

Contraseña del KeyStore:
Alias: pepe
CN (Common Name): PEPE
OU (Organizational Unit): DAM
O (Organization): MONLAU
L (Locality): BARCELONA
ST (State/Province): BARCELONA
C (Country): ES

Generando CSR...

Solicitud CSR generada correctamente.
Alias: pepe
Archivo: data/pepe.csr
DN: C=ES,ST=BARCELONA,L=BARCELONA,O=MONLAU,OU=DAM,CN=PEPE
```

La CSR se guarda en:

```text
data/pepe.csr
```

El archivo se genera en formato PEM.

---

# 11. Listar aliases

El programa tambien permite consultar los aliases almacenados:

```bash
python keytool.py --list
```

Ejemplo:

```text
=== Lista del KeyStore ===

Contraseña del KeyStore:

- pepe
```

Esta funcionalidad permite comprobar que las claves se han almacenado correctamente.

---

# 12. Verificacion de una CSR

El archivo `verify_csr.py` permite comprobar una CSR.

La comprobacion verifica:

* Que el archivo existe.
* Que el archivo contiene una CSR valida.
* Que la firma de la CSR es valida.

Tambien permite mostrar informacion sobre:

* Subject.
* Algoritmo de firma.
* Validez de la firma.
* Tipo de clave publica.

---

# 13. Gestion de errores

La aplicacion controla diferentes situaciones de error para evitar que el programa termine inesperadamente.

## 13.1 Contraseña incorrecta

Si se introduce una contraseña incorrecta para acceder al KeyStore:

```text
Error: Contraseña incorrecta
```

El contenido del KeyStore no se puede descifrar.

---

## 13.2 Alias duplicado

Si se intenta crear una clave utilizando un alias que ya existe:

```text
Error: el alias ya existe.
```

La aplicacion no sobrescribe la clave existente.

---

## 13.3 Alias inexistente

Si se intenta generar una CSR utilizando un alias que no existe:

```text
Error: el alias no existe en el KeyStore.
```

---

## 13.4 Contraseña vacia

No se permite continuar si la contraseña esta vacia:

```text
Error: la contraseña no puede estar vacia.
```

---

## 13.5 Country incorrecto

El codigo de pais debe tener exactamente dos caracteres.

Ejemplo:

```text
C (Country): ESP
```

Resultado:

```text
Error: C debe tener exactamente 2 caracteres.
```

---

# 14. Pruebas

Durante el desarrollo se realizan diferentes pruebas para comprobar el funcionamiento de la aplicacion.

| Nº | Prueba                | Comando / accion                 | Resultado esperado               | Estado |
| -- | --------------------- | -------------------------------- | -------------------------------- | ------ |
| 1  | Mostrar ayuda         | `python keytool.py --help`       | Muestra los comandos disponibles | OK     |
| 2  | Generar clave         | `python keytool.py --genkeypair` | Genera RSA 2048                  | OK     |
| 3  | Guardar clave         | `--genkeypair`                   | Guarda la clave en el KeyStore   | OK     |
| 4  | Alias duplicado       | Crear un alias existente         | Muestra un error                 | OK     |
| 5  | Generar CSR           | `python keytool.py --certreq`    | Genera un archivo `.csr`         | OK     |
| 6  | Listar aliases        | `python keytool.py --list`       | Muestra los aliases              | OK     |
| 7  | Contraseña incorrecta | Introducir password incorrecta   | Rechaza el acceso                | OK     |
| 8  | Alias inexistente     | Introducir alias inexistente     | Muestra un error                 | OK     |
| 9  | Verificar CSR         | Ejecutar `verify_csr.py`         | Comprueba la firma               | OK     |
| 10 | Country incorrecto    | Introducir mas de 2 caracteres   | Muestra un error                 | OK     |

> Las pruebas se actualizaran durante el desarrollo final del proyecto y se incluiran capturas de los resultados obtenidos en la terminal.

---

# 15. Ejemplo de funcionamiento completo

El flujo principal de la aplicacion es:

```text
1. Ejecutar --genkeypair
          ↓
2. Introducir contraseña
          ↓
3. Introducir alias
          ↓
4. Introducir datos CN, OU, O, L, ST y C
          ↓
5. Generar clave RSA 2048
          ↓
6. Guardar clave en KeyStore cifrado
          ↓
7. Ejecutar --certreq
          ↓
8. Introducir contraseña y alias
          ↓
9. Recuperar clave privada
          ↓
10. Generar CSR
          ↓
11. Guardar CSR en formato PEM
          ↓
12. Verificar CSR
```

---

# 16. Seguridad

El proyecto utiliza diferentes mecanismos de seguridad:

* Las contraseñas se solicitan mediante `getpass`, evitando mostrarlas directamente en la terminal.
* El KeyStore se cifra utilizando Fernet.
* La clave utilizada para el cifrado se deriva de la contraseña mediante PBKDF2.
* Se utiliza un salt aleatorio.
* Las claves RSA tienen un tamaño de 2048 bits.
* Las CSR se firman utilizando SHA-256.

---

# 17. Ampliaciones

Además de las funcionalidades obligatorias indicadas en el enunciado, el proyecto incluye funcionalidades adicionales.

### Listado de aliases

```bash
python keytool.py --list
```

Permite consultar las entradas almacenadas en el KeyStore.

### Verificacion de CSR

El proyecto dispone de `verify_csr.py`, que permite comprobar la validez de una solicitud CSR y su firma.

---

# 18. Autores

Proyecto realizado por:

* Ignacio Andrés Leal Escarate
* Nuria Font Sanchez

Curso: CFGS Desarrollo de Aplicaciones Multiplataforma (DAM)

---

# 19. Conclusiones

Con este proyecto se ha desarrollado una simulacion de la herramienta Java Keytool utilizando Python.

La aplicacion permite trabajar con claves RSA, almacenamiento persistente y cifrado de informacion, asi como generar solicitudes CSR.

El proyecto tambien permite practicar conceptos relacionados con criptografia, estructuras modulares, gestion de errores, interfaces CLI, persistencia de datos y trabajo colaborativo mediante Git y GitHub.

