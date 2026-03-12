from io import BytesIO
from typing import Generator

from asn1 import (
    ASN1,
    CONSTRUCTED,
    CONSTRUCTION,
    CONSTRUCTION_OPTIONS,
    CTAG_TO_TYPE,
    PRIMITIVE,
    PTAG_TO_TYPE,
    ConstructedASN1,
    PrimitiveASN1,
)


class Parser:
    file: BytesIO = BytesIO()

    def __init__(self, file: BytesIO):
        self.file = file

    @staticmethod
    def _parse_identifier_octets(bytes: BytesIO) -> tuple[int, CONSTRUCTION, int, int]:

        def _parse_extended_octets(bytes: BytesIO) -> Generator[int]:
            while True:
                octet = bytes.read(1)[0]
                yield octet
                # left most bit tells whether theres more octets
                if not octet >> 7:
                    break

        octet = bytes.read(1)[0]
        tag_class = octet >> 6

        # clear left most 2 bits and right most 5 bits
        construction_bit = (octet & ~(octet >> 6 << 6)) >> 5
        # 6th left most bit marks construction
        construction = CONSTRUCTION_OPTIONS[construction_bit]

        # right most 5 bits marks tag type or whether it's stored in the next octet
        tag_type = octet & ~(octet >> 5 << 5)

        size = 1
        # get extended tag type value
        # 11111 means extended form
        if tag_type == 31:
            tag_type = 0
            for octet in _parse_extended_octets(bytes=bytes):
                tag_type <<= 7
                tag_type += octet & ~(1 << 7)
                size += 1

        return tag_class, construction, tag_type, size

    @staticmethod
    def _parse_length_octets(bytes: BytesIO) -> tuple[int, int]:
        octet = bytes.read(1)[0]

        long_form = octet >> 7
        length = octet & ~(octet >> 7)

        # if short form then length represents the length of data
        if not long_form:
            return length, 1

        num_octets = length
        # if long form then length is the number of octets housing the length
        for _ in range(num_octets):
            curr_octet = bytes.read(1)[0]
            length <<= 8
            length += curr_octet

        return length, num_octets + 1

    @staticmethod
    def _parse_primitive_data(bytes: BytesIO, size: int) -> bytes:
        return bytes.read(size)

    def _parse_primitive(self, tag_type: int, data_size, identifier_size: int):
        ASN1_TYPE: type[PrimitiveASN1] | None = PTAG_TO_TYPE.get(tag_type, None)
        if not ASN1_TYPE or ASN1_TYPE.permitted_construction != PRIMITIVE:
            raise Exception(
                f"Inconsistent construction and type tag of data {ASN1_TYPE}, {tag_type}"
            )

        data = self._parse_primitive_data(self.file, data_size)

        return ASN1_TYPE(data=data, size=identifier_size + data_size)

    def _parse_constructed(
        self, tag_type: int, data_size: int, identifier_size: int
    ) -> ConstructedASN1:
        ASN1_TYPE: type[ConstructedASN1] | None = CTAG_TO_TYPE.get(tag_type, None)
        if not ASN1_TYPE or ASN1_TYPE.permitted_construction != CONSTRUCTED:
            raise Exception(
                f"Inconsistent construction and type tag of data type: {ASN1_TYPE}, tag_type: {tag_type}."
            )

        node = ASN1_TYPE(size=identifier_size + data_size)
        length_remaining = data_size
        while length_remaining > 0:
            next_node = self.parse()
            node.components.append(next_node)
            length_remaining -= next_node.size

        if length_remaining < 0:
            raise Exception(
                f"Length of nodes children is larger than expected. Expected size: {data_size}, got: {data_size - length_remaining}"
            )

        return node

    def parse(self) -> ASN1:
        tag_class, construction, tag_type, identifier_size = (
            self._parse_identifier_octets(self.file)
        )
        if tag_class == 0:
            pass

        data_size, length_size = self._parse_length_octets(self.file)
        identifier_size += length_size

        if construction == PRIMITIVE:
            return self._parse_primitive(
                tag_type=tag_type, data_size=data_size, identifier_size=identifier_size
            )

        return self._parse_constructed(
            tag_type=tag_type, data_size=data_size, identifier_size=identifier_size
        )
