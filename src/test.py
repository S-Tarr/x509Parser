import datetime
import traceback
from io import BytesIO

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from parser import Parser


def generate_test_der():
    # 1. Generate a private key for signing
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # 2. Build the certificate details
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ASN1-Test-Lab"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test-parser.local"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    der_bytes = cert.public_bytes(serialization.Encoding.DER)
    return cert


def test_extended_identifier_primitive():
    file = BytesIO(b"\x1f\x02\x02\x00\x80")
    parser = Parser(file)
    parsed_int = parser.parse()
    print(parsed_int)
    if str(parsed_int) != "Integer : 128":
        return False

    return True


def test_int_primitive():
    file = BytesIO(b"\x02\x02\x00\x80")
    data_parser = Parser(file)
    parsed_int = data_parser.parse()
    print(parsed_int)
    if str(parsed_int) != "Integer : 128":
        return False

    return True


def test_ia5_string():
    file = BytesIO(b"\x16\x0e\x41\x6e\x79\x62\x6f\x64\x79\x20\x74\x68\x65\x72\x65\x3f")
    data_parser = Parser(file)
    parsed_str = data_parser.parse()
    print(parsed_str)
    if str(parsed_str) != "IA5String : Anybody there?":
        return False

    return True


def test_bit_string():
    file = BytesIO(b"\x03\x03\x01\x00\x02")
    data_parser = Parser(file)
    parsed_str = data_parser.parse()
    print(parsed_str)
    if str(parsed_str) != "BitString : 00000001":
        return False

    return True


def test_constructed():
    file = BytesIO(
        b"\x30\x13\x02\x01\x05\x16\x0e\x41\x6e\x79\x62\x6f\x64\x79\x20\x74\x68\x65\x72\x65\x3f"
    )
    data_parser = Parser(file)
    parsed_int = data_parser.parse()
    print(parsed_int)
    return True


def test_nested_constructed():
    file = BytesIO(
        b"\x30\x15\x30\x13\x02\x01\x05\x16\x0e\x41\x6e\x79\x62\x6f\x64\x79\x20\x74\x68\x65\x72\x65\x3f"
    )
    data_parser = Parser(file)
    parsed = data_parser.parse()
    print(parsed)
    return True


def test_full_cert():
    # Usage for your parser
    cert = generate_test_der()
    der_bytes = cert.public_bytes(serialization.Encoding.DER)
    print(f"Generated {len(der_bytes)} bytes of DER data.")
    # You can now wrap this in BytesIO and pass it to your parse_content method
    file = BytesIO(der_bytes)
    parser = Parser(file)
    parsed_cert = parser.parse()
    print(parsed_cert)
    return True


tests = [
    test_extended_identifier_primitive,
    test_int_primitive,
    test_ia5_string,
    test_bit_string,
    test_constructed,
    test_nested_constructed,
    test_full_cert,
]

passed = 0
for test in tests:
    try:
        if not test():
            print(f"Failed test: {test.__name__}")
        else:
            passed += 1
    except Exception as e:
        print(f"Error: {e} while running test: {test.__name__}")
        traceback.print_exc()

print("\nPassed tests: ", passed)
