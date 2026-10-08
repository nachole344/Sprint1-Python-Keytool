from cryptography.hazmat.primitives.asymmetric import rsa

from keystore import (
    save_key,
    get_key,
    alias_exists
)

from csr import (
    create_subject,
    generate_csr_for_alias,
    save_csr
)


# ==========================================
# ================ DATOS ==================
# ==========================================

password = "1234"

alias = "pepe"

common_name = "PEPE"
organizational_unit = "DAM"
organization = "MONLAU"
locality = "BARCELONA"
state = "BARCELONA"
country = "ES"


# ==========================================
# ======== GENERAR CLAVE PRIVADA ==========
# ==========================================

print("Generando clave privada...")

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

print(
    "Clave privada generada correctamente"
)


# ==========================================
# ========== CREAR SUBJECT ================
# ==========================================

subject = create_subject(
    common_name,
    organizational_unit,
    organization,
    locality,
    state,
    country
)

print(
    "Subject creado correctamente"
)


# ==========================================
# ========= GUARDAR EN KEYSTORE ===========
# ==========================================

print(
    "Guardando clave en el KeyStore..."
)

if alias_exists(
    alias,
    password
):

    print(
        "El alias ya existe."
    )

else:

    save_key(
        alias,
        private_key,
        subject,
        password
    )

    print(
        "Clave guardada correctamente"
    )


# ==========================================
# ============ RECUPERAR CLAVE ============
# ==========================================

print(
    "Recuperando clave del KeyStore..."
)

key_data = get_key(
    alias,
    password
)

print(
    "Clave recuperada correctamente"
)

print(
    "Alias:",
    alias
)


# ==========================================
# ============ GENERAR CSR ================
# ==========================================

print(
    "Generando CSR..."
)

csr = generate_csr_for_alias(
    alias,
    password,
    common_name,
    organizational_unit,
    organization,
    locality,
    state,
    country
)

print(
    "CSR generado correctamente"
)


# ==========================================
# ============== GUARDAR CSR ==============
# ==========================================

filepath = save_csr(
    csr,
    "pepe.csr"
)

print(
    "CSR guardado correctamente"
)

print(
    "Archivo:",
    filepath
)


# ==========================================
# ================ FINAL ===================
# ==========================================

print()
print(
    "==================================="
)
print(
    "       PRUEBA COMPLETADA"
)
print(
    "==================================="
)