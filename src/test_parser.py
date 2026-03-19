from io import BytesIO

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from parser import Parser
from x509Certificate import X509Certificate


@pytest.fixture(scope="module")
def sample_cert_der():
    import datetime

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(65537, 2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(x509.NameOID.COMMON_NAME, "test.local")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(1)
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_int_primitive():
    data = b"\x02\x02\x00\x80"
    parser = Parser(BytesIO(data))
    result = parser.parse()

    assert str(result) == "Integer :== 128"


def test_ia5_string():
    data = b"\x16\x0e\x41\x6e\x79\x62\x6f\x64\x79\x20\x74\x68\x65\x72\x65\x3f"
    parser = Parser(BytesIO(data))
    result = parser.parse()

    assert str(result) == "IA5String :== Anybody there?"


def test_bit_string():
    data = b"\x03\x03\x01\x01\x02"
    parser = Parser(BytesIO(data))
    result = parser.parse()

    assert str(result) == " :== BitString 0000000010000001"


def test_full_cert_parsing(sample_cert_der):
    parser = Parser(BytesIO(sample_cert_der))
    result = parser.parse()

    assert result is not None
    x509_obj = X509Certificate(result)

    assert x509_obj.get_version_number() == "v3"


def test_v1_cert_parsing(sample_cert_der):
    parser = Parser(BytesIO(sample_cert_der))
    parsed = parser.parse()
    # Remove the version field from the certificate
    parsed.components[0].components.pop(0)  # type: ignore

    cert = X509Certificate(parsed)
    assert cert.get_version_number() == "v1"


def test_invalid_asn1():
    invalid_data = b"\x30\x03\x02\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # Declares 3 bytes but provides 12
    parser = Parser(BytesIO(invalid_data))

    with pytest.raises(Exception):
        parser.parse()
