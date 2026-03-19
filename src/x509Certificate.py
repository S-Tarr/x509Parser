from io import BytesIO

from asn1 import ASN1, ConstructedASN1, Integer, PrimitiveASN1
from parser import Parser


class X509Certificate:
    cert_indicies = {
        "tbsCertificate": 0,
        "signatureAlgorithm": 1,
        "signatureValue": 2,
    }
    tbs_indicies = {
        "version": 0,
        "serialNumber": 1,
        "signature": 2,
        "issuer": 3,
        "validity": 4,
        "subject": 5,
        "subjectPublicKeyInfo": 6,
        "issuerUniqueID": 7,
        "subjectUniqueID": 8,
        "extensions": 9,
    }

    def __init__(self, certificate: ASN1):
        self._assign_components(certificate=certificate)

    @classmethod
    def from_bytes(cls, bytes: BytesIO):
        cls(certificate=Parser(bytes).parse())

    def _assign_components(self, certificate: ASN1):
        self.certificate = self.validated_certificate(certificate)
        self.certificate.label = "Certificate"

        # top level certificate fields
        self.tbs_cert = self._get_tbs_cert()
        self.signature_algorithm = self._get_signature_algorithm()
        self.signature_value = self._get_signature_value()

        # tbs certificate fields
        self.version = self._get_version()
        self.serial_number = self._get_serial_number()
        self.signature = self._get_signature()
        self.issuer = self._get_issuer()
        self.validity = self._get_validity()
        self.subject = self._get_subject()
        self.subject_public_key_info = self._get_subject_public_key_info()
        self.issuer_unique_id = self._get_issuer_unique_id()
        self.subject_unique_id = self._get_subject_unique_id()
        self.extensions = self._get_extensions()

    @staticmethod
    def validated_certificate(node: ASN1) -> ConstructedASN1:
        if node and isinstance(node, ConstructedASN1):
            return node
        raise ValueError("Invalid certificate")

    @staticmethod
    def validated_tbs_cert(node: ASN1) -> ConstructedASN1:
        if node is not None and isinstance(node, ConstructedASN1):
            return node
        raise ValueError("Invalid TBS certificate")

    def _get_tbs_cert(self) -> ConstructedASN1:
        node = self.validated_tbs_cert(
            self.certificate.components[self.cert_indicies["tbsCertificate"]]
        )
        node.label = "tbsCertificate"
        return node

    @staticmethod
    def validated_version(node: ASN1) -> ConstructedASN1:
        if node and isinstance(node, ConstructedASN1):
            if (
                len(node.components) == 1
                and isinstance(node.components[0], Integer)
                and node.components[0].get_value() in [1, 2]
            ):
                return node
        raise ValueError("Invalid version")

    def _get_version(self) -> ConstructedASN1 | None:
        if (
            not (node := self.tbs_cert.components[self.tbs_indicies["version"]])
            or node.tag_class != 2
            or node.given_tag_number != 0
        ):
            return None
        if node := self.validated_version(node):
            node.label = "version"
            return node
        return None

    def get_version_number(self) -> str:
        if self.version and (version_node := self.validated_version(self.version)):
            version = version_node.components[0].get_value()  # type: ignore
            version_map = {1: "v2", 2: "v3"}
            return version_map.get(int(version), "unknown")
        if not self.version:
            return "v1"
        raise Exception("Invalid version")

    @staticmethod
    def validate_serial_number(node: ASN1) -> Integer:
        if node and isinstance(node, Integer):
            return node
        raise ValueError("Invalid serial number")

    def _get_serial_number(self) -> Integer:
        if self.version:
            node = self._get_tbs_cert().components[self.tbs_indicies["serialNumber"]]
        else:
            node = self._get_tbs_cert().components[
                self.tbs_indicies["serialNumber"] - 1
            ]
        node = self.validate_serial_number(node)
        node.label = "serialNumber"
        return node

    @staticmethod
    def validated_signature(node: ASN1) -> ConstructedASN1:
        if node and isinstance(node, ConstructedASN1):
            return node
        raise ValueError("Invalid signature")

    def _get_signature(self) -> ConstructedASN1:
        if self.version:
            node = self._get_tbs_cert().components[self.tbs_indicies["signature"]]
        else:
            node = self._get_tbs_cert().components[self.tbs_indicies["signature"] - 1]
        node = self.validated_signature(node)
        node.label = "signature"
        return node

    @staticmethod
    def validated_issuer(node: ASN1) -> ConstructedASN1:
        if node is not None and isinstance(node, ConstructedASN1):
            return node
        raise ValueError("Invalid issuer")

    def _get_issuer(self) -> ConstructedASN1:
        if self.version:
            node = self._get_tbs_cert().components[self.tbs_indicies["issuer"]]
        else:
            node = self._get_tbs_cert().components[self.tbs_indicies["issuer"] - 1]
        node = self.validated_issuer(node)
        node.label = "issuer"
        return node

    @staticmethod
    def validated_validity(node: ASN1) -> ConstructedASN1:
        if node is not None and isinstance(node, ConstructedASN1):
            return node
        raise ValueError("Invalid validity")

    def _get_validity(self) -> ConstructedASN1:
        if self.version:
            node = self._get_tbs_cert().components[self.tbs_indicies["validity"]]
        else:
            node = self._get_tbs_cert().components[self.tbs_indicies["validity"] - 1]
        node = self.validated_validity(node)
        node.label = "validity"
        return node

    @staticmethod
    def validated_subject(node: ASN1) -> ConstructedASN1:
        if node is not None and isinstance(node, ConstructedASN1):
            return node
        raise ValueError("Invalid subject")

    def _get_subject(self) -> ConstructedASN1:
        if self.version:
            node = self._get_tbs_cert().components[self.tbs_indicies["subject"]]
        else:
            node = self._get_tbs_cert().components[self.tbs_indicies["subject"] - 1]
        node = self.validated_subject(node)
        node.label = "subject"
        return node

    @staticmethod
    def validated_subject_public_key_info(node: ASN1) -> ConstructedASN1:
        if node is not None and isinstance(node, ConstructedASN1):
            return node
        raise ValueError("Invalid subject public key info")

    def _get_subject_public_key_info(self) -> ConstructedASN1:
        if self.version:
            node = self._get_tbs_cert().components[
                self.tbs_indicies["subjectPublicKeyInfo"]
            ]
        else:
            node = self._get_tbs_cert().components[
                self.tbs_indicies["subjectPublicKeyInfo"] - 1
            ]
        node = self.validated_subject_public_key_info(node)
        node.label = "subjectPublicKeyInfo"
        return node

    def _find_issuer_unique_id(self) -> ASN1 | None:
        for node in self._get_tbs_cert().components:
            if node.tag_class == 2 and node.given_tag_number == 1:
                return node

        return None

    @staticmethod
    def validated_issuer_unique_id(node: ASN1) -> ConstructedASN1:
        if isinstance(node, ConstructedASN1):
            return node
        raise ValueError("Invalid issuer unique id")

    def _get_issuer_unique_id(self) -> ConstructedASN1 | None:
        if not (node := self._find_issuer_unique_id()):
            return None
        node = self.validated_issuer_unique_id(node)
        node.label = "issuerUniqueID"
        return node

    def _find_subject_unique_id(self) -> ASN1 | None:
        for node in self._get_tbs_cert().components:
            if node.tag_class == 2 and node.given_tag_number == 2:
                return node

        return None

    @staticmethod
    def validated_subject_unique_id(node: ASN1) -> ConstructedASN1:
        if isinstance(node, ConstructedASN1):
            return node
        raise ValueError("Invalid subject unique id")

    def _get_subject_unique_id(self) -> ConstructedASN1 | None:
        if not (node := self._find_subject_unique_id()):
            return None
        node = self.validated_subject_unique_id(node)
        node.label = "subjectUniqueID"
        return node

    def _find_extensions(self) -> ASN1 | None:
        for node in self._get_tbs_cert().components:
            if node.tag_class == 2 and node.given_tag_number == 3:
                return node

        return None

    @staticmethod
    def validated_extensions(node: ASN1) -> ConstructedASN1:
        if isinstance(node, ConstructedASN1):
            return node
        raise ValueError("Invalid extensions")

    def _get_extensions(self) -> ConstructedASN1 | None:
        if not (node := self._find_extensions()):
            return None
        node = self.validated_extensions(node)
        node.label = "extensions"
        return node

    @staticmethod
    def validated_signature_algorithm(node: ASN1) -> ConstructedASN1:
        if node is not None and isinstance(node, ConstructedASN1):
            return node
        raise ValueError("Invalid signature algorithm")

    def _get_signature_algorithm(self) -> ConstructedASN1:
        node = self.validated_signature_algorithm(
            self.certificate.components[self.cert_indicies["signatureAlgorithm"]]
        )
        node.label = "signatureAlgorithm"
        return node

    @staticmethod
    def validated_signature_value(node: ASN1) -> PrimitiveASN1:
        if node and isinstance(node, PrimitiveASN1):
            return node
        raise ValueError("Invalid signature value")

    def _get_signature_value(self) -> PrimitiveASN1:
        node = self.validated_signature_value(
            self.certificate.components[self.cert_indicies["signatureValue"]]
        )
        node.label = "signatureValue"
        return node

    def __str__(self) -> str:
        return str(self.certificate)
