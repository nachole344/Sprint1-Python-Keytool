# Java Keytool en Python

## 1. Descripción del proyecto

Este proyecto consiste en la representacion de algunas de las funciones de Java Keytool utilizando Python.

Java Keytool es una herramienta que permite gestionar claves criptográficas y certificados digitales. En este proyecto se ha desarrollado una versión simplificada que permite generar claves RSA, guardarlas y crear solicitudes de certificados digitales (CSR).

El objetivo principal es entender cómo funciona la criptografía.

## 2. Objetivos

Los objetivos principales de la práctica son:

- Generar claves privadas RSA de 2048 bits.
- Crear la información de identificación necesaria para una solicitud de certificado.
- Guardar las claves dentro de un keystore cifrado.
- Recuperar las claves mediante un alias y una contraseña.
- Generar solicitudes de certificados digitales CSR.
- Guardar las solicitudes generadas en archivos.
- Trabajar con módulos, funciones, archivos y excepciones en Python.

## 3. Tecnologías utilizadas

- **Python:** lenguaje que hemos usado para desarrollar el programa.
- **cryptography:** biblioteca usada para trabajar con claves RSA, cifrado y certificados.
- **JSON:** formato para organizar los datos almacenados en el keystore.
- **Fernet:** mecanismo de cifrado para proteger la información almacenada.
- **PBKDF2:** mecanismo para derivar una clave de cifrado a partir de una contraseña.

## 4. Estructura del proyecto

El proyecto está organizado en diferentes archivos para separar las funcionalidades y facilitar su mantenimiento.

- `crypto_utils.py`: funciones para generar claves RSA y operaciones criptográficas.
- `keystore.py`: el encargado de guardar y recuperar las claves.
- `csr.py`: funciones para crear la información del titular, generar solicitudes CSR y guardarlas.
- `requirements.txt`: dependencias necesarias para ejecutar el proyecto.
- `README.md`: la documentación del proyecto.
- `data/keystore.enc`: donde se almacena el keystore cifrado (se genera durante la ejecución).

## 5. Funcionamiento del programa

### 5.1. Generación de claves RSA

El programa genera una clave privada RSA de 2048 bits. Esta clave se usara para realizar las operaciones criptográficas necesarias.

La clave privada debe mantenerse protegida, no se ha de compartir con otras personas.

### 5.2. Almacenamiento de las claves

Las claves se guardan en un keystore utilizando un alias para identificar cada entrada.

Antes de almacenarse, la información se protege mediante cifrado. Para ello, se utiliza Fernet y una clave derivada de la contraseña mediante PBKDF2.

De esta manera, el contenido del archivo no se guarda directamente como información legible.

### 5.3. Recuperación de las claves

El programa permite recuperar una clave almacenada utilizando su alias y la contraseña correspondiente.

Si los datos introducidos son incorrectos o la información no se puede descifrar, el programa debe tratar el error adecuadamente.

### 5.4. Generación de solicitudes CSR

Una CSR (*Certificate Signing Request*) es una solicitud de firma de certificado.

Para crearla, el programa utiliza la clave privada y la información del titular, como el nombre, la organización, la localidad y el país.

La solicitud generada se guardara en un archivo con extensión `.csr`.

Una CSR no es un certificado digital firmado: es una solicitud que se puede enviar a una autoridad de certificación.

## 6. Instalación

Para ejecutar el proyecto, es necesario tener Python instalado y disponer de las dependencias correspondientes.

Primero, se instala la biblioteca necesaria:

```bash
python -m pip install -r requirements.txt
```

## 9. Seguridad

En este proyecto se aplican diferentes mecanismos de seguridad:

- RSA de 2048 bits para la generación de claves.
- Cifrado Fernet para proteger el contenido del keystore.
- PBKDF2 con 600.000 iteraciones para derivar la clave de cifrado a partir de la contraseña.
- Uso de contraseñas para controlar el acceso a las claves almacenadas.
- Separación de las funciones en módulos para facilitar su mantenimiento.

Estas medidas forman parte de los mecanismos de protección de información. Aun así, es una simulación no debe considerarse equivalente a una herramienta profesional de gestión de claves.

## 10. Conclusión

Con esta práctica ayudo a poder trabajar con criptografía en Python y a separar un programa en diferentes módulos.

También con la generación de claves RSA, el almacenamiento cifrado de información, la recuperación de claves y la creación de solicitudes CSR.

Además, comprender la importancia de las contraseñas, el tratamiento de errores y las pruebas para verificar que las diferentes partes del programa funcionan correctamente.
