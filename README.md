# x509 Certificate Parser

## Limited ASN1 DER parsing for x509 certificates.

### Implemented without any external dependencies (besides for testing)

## Usage
```python
parser = Parser(open("cert.der"))
parsed = parser.parse()

cert = X509Certificate(parsed)
version = cert.get_version_number()
```
## printed parsed Certificate Example
```
Certificate :== Sequence {
    tbsCertificate :== Sequence {
        version :== ConstructedASN1 {
            Integer :== 2
        },
        serialNumber :== Integer 123915360494587376869063920158328246770400847392,
        signature :== Sequence {
            ObjectIdentifier :== 1.2.134.72.134.247.13.1.1.11,
            PrimitiveASN1 :==
        },
        issuer :== Sequence {
            ConstructedASN1 {
                Sequence {
                    ObjectIdentifier :== 2.5.4.3,
                    PrimitiveASN1 :== 74 65 73 74 2e 6c 6f 63 61 6c
                }
            }
        },
        validity :== Sequence {
            PrimitiveASN1 :== 32 36 30 33 31 39 31 38 30 33 34 35 5a,
            PrimitiveASN1 :== 32 36 30 33 32 30 31 38 30 33 34 35 5a
        },
        subject :== Sequence {
            ConstructedASN1 {
                Sequence {
                    ObjectIdentifier :== 2.5.4.3,
                    PrimitiveASN1 :== 74 65 73 74 2e 6c 6f 63 61 6c
                }
            }
        },
        subjectPublicKeyInfo :== Sequence {
            Sequence {
                ObjectIdentifier :== 1.2.134.72.134.247.13.1.1.1,
                PrimitiveASN1 :==
            },
             :== BitString 0011000010000010000000010000101000000010... (270 bits)
        }
    },
    signatureAlgorithm :== Sequence {
        ObjectIdentifier :== 1.2.134.72.134.247.13.1.1.11,
        PrimitiveASN1 :==
    },
    signatureValue :== BitString 0100000000111100100100100011010001010100... (256 bits)
}
```

## Supported ASN1 DER structures
- Integer
- BitString
- OctetString
- Sequence
- Set
- IA5String
- ObjectIdentifier
- ...All others are interpretted as primitive or constructed generics


## Future
### Editing
With all the values turned into objects and labeled, adding the functionality for editing the values seems like a useful next step.
The thought is to store the offsets of the each asn1 object in the original certificate and make edits within the original file. This could keep from having to generate an all new certificate. There will be some difficulties with tracking the changing offsets as fields shrink and get bigger.

### More types
There are only a small set of ASN1 types implemented right now and it would be make the project more valuable if more were added

### Usage
Currently the repo will have to be cloned to use any of this, but if in the future features like editing are added, the project should be added to PyPi.
