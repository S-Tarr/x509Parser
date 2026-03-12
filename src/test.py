import traceback
from io import BytesIO

from parser import Parser


def test_primitive():
    file = BytesIO(b"\x02\x02\x00\x80")
    parser = Parser(file)
    parsed_int = parser.parse()
    print(parsed_int)
    if str(parsed_int) != "Integer : 128":
        return False

    return True


def test_constructed():
    file = BytesIO(
        b"\x30\x13\x02\x01\x05\x16\x0e\x41\x6e\x79\x62\x6f\x64\x79\x20\x74\x68\x65\x72\x65\x3f"
    )
    parser = Parser(file)
    parsed_int = parser.parse()
    print(parsed_int)
    return True


tests = [test_primitive, test_constructed]

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
