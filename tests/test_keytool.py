from crypto_utils import generate_rsa_key


def test_rsa_2048():
    private_key = generate_rsa_key()

    assert private_key.key_size == 2048