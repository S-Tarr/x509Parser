from abc import ABC, abstractmethod
from typing import Literal

PRIMITIVE = "Primitive"
CONSTRUCTED = "Constructed"
CONSTRUCTION = Literal["Primitive", "Constructed", None]
CONSTRUCTION_OPTIONS = (PRIMITIVE, CONSTRUCTED)


# Classes for the asn1 fields
class ASN1(ABC):
    permitted_construction = None

    def __init__(self, size: int, **kwargs):
        # in bytes
        self.size = size


class PrimitiveASN1(ASN1, ABC):
    data: bytes = b""
    value = None
    permitted_construction = PRIMITIVE

    def __init__(self, data: bytes, **kwargs):
        super().__init__(**kwargs)
        self.data = data

    @abstractmethod
    def _parse_data(self):
        pass

    def __str__(self):
        return self.__class__.__name__ + " : " + str(self.value)


class ConstructedASN1(ASN1):
    permitted_construction = CONSTRUCTED
    components: list[ASN1] = []

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def __str__(self):
        out = f"{self.__class__.__name__} :== {{\n"
        for component in self.components:
            out += f"    {component.__class__.__name__},\n"

        out += "}"
        return out


class Integer(PrimitiveASN1):
    tag_number = 0x2
    value: int = 0

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._parse_data()

    def _parse_data(self):
        self.value = int.from_bytes(self.data)


class IA5STRING(PrimitiveASN1):
    tag_number = 0x16
    value: str = ""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._parse_data()

    def _parse_data(self):
        self.value = self.data.decode("ascii")


class Sequence(ConstructedASN1):
    tag_number = 0x10

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


PTAG_TO_TYPE: dict[int, type[PrimitiveASN1]] = {
    Integer.tag_number: Integer,
    IA5STRING.tag_number: IA5STRING,
}
CTAG_TO_TYPE: dict[int, type[ConstructedASN1]] = {Sequence.tag_number: Sequence}
