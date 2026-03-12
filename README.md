# x509 Certificate Parser

## Limited ASN1 DER parsing for x509 certificates.

### Implemented without any external dependencies

## Usage
```python
from x509Parser import Parser

cert = Parser(open("cert.der").read())
print(cert.parse())
```

## Supported ASN1 DER structures
- Integer
- BitString
- OctetString
- Sequence
- Set
- IA5String
