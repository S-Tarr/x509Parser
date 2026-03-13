import textwrap
from abc import ABC
from io import BytesIO
from typing import Literal

from bitarray import bitarray

PRIMITIVE = "Primitive"
CONSTRUCTED = "Constructed"
CONSTRUCTION = Literal["Primitive", "Constructed", None]
CONSTRUCTION_OPTIONS = (PRIMITIVE, CONSTRUCTED)


# Classes for the asn1 fields
class ASN1(ABC):
    permitted_construction = None

    def __init__(
        self,
        size: int = 0,
        label: str = "",
        tag_class: int = 0,
        tag_number: int = 0,
        **kwargs,
    ):
        # in bytes
        self.size = size
        self.label = label
        self.tag_class = tag_class
        self.given_tag_number = tag_number


class PrimitiveASN1(ASN1):
    permitted_construction = PRIMITIVE

    def __init__(self, data: bytes = b"", **kwargs):
        super().__init__(**kwargs)
        self.data: bytes = data
        self.value_decoded = False
        self.value = None

    def _decode_data(self):
        self.value = self.data
        self.value_decoded = True

    def get_value(self):
        self._decode_data()
        if self.value:
            return self.value
        return self.data

    @staticmethod
    def parse_content(bytes: BytesIO, size: int):
        return bytes.read(size)

    def __str__(self):
        self._decode_data()
        return self.__class__.__name__ + " :== " + str(self.data.hex(" "))


class ConstructedASN1(ASN1):
    permitted_construction = CONSTRUCTED

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.components: list[ASN1] = []

    def __str__(self):
        content = ",\n".join(str(c) for c in self.components)
        wrapped = textwrap.indent(content, "    ")
        if self.label:
            return f"{self.label} :== " + f"{self.__class__.__name__} {{\n{wrapped}\n}}"
        return f"{self.__class__.__name__} {{\n{wrapped}\n}}"


class Integer(PrimitiveASN1):
    tag_number = 0x2

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def _decode_data(self):
        if self.value_decoded:
            return
        self.value_decoded = True
        self.value = int.from_bytes(self.data)

    def __str__(self):
        if self.label:
            return (
                f"{self.label} :== "
                + self.__class__.__name__
                + " "
                + str(self.get_value())
            )
        return self.__class__.__name__ + " :== " + str(self.get_value())


class BitString(PrimitiveASN1):
    tag_number = 0x3

    def __init__(self, unused_bits: int = 0, **kwargs):
        super().__init__(**kwargs)
        self.unused_bits = unused_bits

    def _decode_data(self):
        if self.value_decoded:
            return
        self.value_decoded = True
        self.value = self.data

    @staticmethod
    def parse_content(bytes: BytesIO, size: int):
        try:
            unused_bits = int.from_bytes(bytes.read(1))
            data = bytes.read(size - 1)
            ba = bitarray()
            ba.frombytes(data)
            ba >>= unused_bits
            return ba.tobytes()
        except Exception as e:
            print(f"Error parsing BitString: {e}")
            return b""

    def __str__(self):
        value = self.get_value()
        res = (
            f"{self.label} :== "
            + self.__class__.__name__
            + " "
            + "".join(f"{byte:08b}" for byte in value[:5])
        )
        return res + f"... ({len(value)} bits)" if len(value) > 5 else res


class ObjectIdentifier(PrimitiveASN1):
    tag_number = 0x06

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def _decode_data(self):
        if self.value_decoded:
            return
        self.value_decoded = True
        first_byte = self.data[0]
        self.value = str(first_byte // 40) + "." + str(first_byte % 40)
        for byte in self.data[1:]:
            self.value += "." + str(byte)

    def __str__(self):
        value = self.get_value()
        if self.label:
            return f"{self.label} :== " + self.__class__.__name__ + " " + str(value)
        return self.__class__.__name__ + " :== " + str(value)


class IA5String(PrimitiveASN1):
    tag_number = 0x16

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def _decode_data(self):
        if self.value_decoded:
            return
        self.value_decoded = True
        self.value = self.data.decode("ascii")

    def __str__(self):
        value = self.get_value()
        if self.label:
            return f"{self.label} :== " + self.__class__.__name__ + " " + str(value)
        return self.__class__.__name__ + " :== " + str(value)


class Sequence(ConstructedASN1):
    tag_number = 0x10

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class Set(ConstructedASN1):
    tag_number = 0x11

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


PTAG_TO_TYPE: dict[int, type[PrimitiveASN1]] = {
    Integer.tag_number: Integer,
    IA5String.tag_number: IA5String,
    BitString.tag_number: BitString,
    ObjectIdentifier.tag_number: ObjectIdentifier,
}
CTAG_TO_TYPE: dict[int, type[ConstructedASN1]] = {Sequence.tag_number: Sequence}
