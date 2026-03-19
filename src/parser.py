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
        tag_number = octet & ~(octet >> 5 << 5)

        size = 1
        # get extended tag type value
        # 11111 means extended form
        if tag_number == 31:
            tag_number = 0
            for octet in _parse_extended_octets(bytes=bytes):
                tag_number <<= 7
                tag_number += octet & ~(1 << 7)
                size += 1

        return tag_class, construction, tag_number, size

    @staticmethod
    def _parse_length_octets(bytes: BytesIO) -> tuple[int, int]:
        octet = bytes.read(1)[0]

        long_form = octet >> 7
        length = octet & ~128

        # if short form then length represents the length of data
        if not long_form:
            return length, 1

        num_octets = length
        length = 0
        # if long form then length is the number of octets housing the length
        for _ in range(num_octets):
            curr_octet = bytes.read(1)[0]
            length <<= 8
            length += curr_octet

        return length, num_octets + 1

    @staticmethod
    def _parse_primitive_data(bytes: BytesIO, size: int) -> bytes:
        return bytes.read(size)

    def _parse_primitive(
        self, tag_class: int, tag_number: int, data_size, identifier_size: int
    ):
        ASN1_TYPE: type[PrimitiveASN1] | None = PTAG_TO_TYPE.get(
            tag_number, PrimitiveASN1
        )
        if not ASN1_TYPE or ASN1_TYPE.permitted_construction != PRIMITIVE:
            raise Exception(
                f"Inconsistent construction and type tag of data {ASN1_TYPE}, {tag_number}"
            )

        node = ASN1_TYPE(
            tag_class=tag_class, tag_number=tag_number, size=identifier_size + data_size
        )
        node.data = ASN1_TYPE.parse_content(bytes=self.file, size=data_size)
        return node

    def _parse_constructed(
        self, tag_class: int, tag_number: int, data_size: int, identifier_size: int
    ) -> ConstructedASN1:
        ASN1_TYPE: type[ConstructedASN1] | None = CTAG_TO_TYPE.get(
            tag_number, ConstructedASN1
        )
        if not ASN1_TYPE or ASN1_TYPE.permitted_construction != CONSTRUCTED:
            raise Exception(
                f"Inconsistent construction and type tag of data type: {ASN1_TYPE}, tag_number: {tag_number}."
            )

        node = ASN1_TYPE(
            tag_class=tag_class, tag_number=tag_number, size=identifier_size + data_size
        )
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
        tag_class, construction, tag_number, identifier_size = (
            self._parse_identifier_octets(self.file)
        )

        data_size, length_size = self._parse_length_octets(self.file)
        identifier_size += length_size

        if construction == PRIMITIVE:
            return self._parse_primitive(
                tag_class=tag_class,
                tag_number=tag_number,
                data_size=data_size,
                identifier_size=identifier_size,
            )

        return self._parse_constructed(
            tag_class=tag_class,
            tag_number=tag_number,
            data_size=data_size,
            identifier_size=identifier_size,
        )
