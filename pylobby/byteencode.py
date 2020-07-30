def uint16(number: int) -> bytes:
    assert 0 <= number < 2 ** 16, "ERROR encoding invalid uint16: {}".format(number)
    (high, low) = divmod(number, 256)
    return bytes([high, low])


def uint8(number: int) -> bytes:
    assert 0 <= number < 256, "ERROR encoding invalid uint8: {}".format(number)
    return bytes([number])


def ipaddr(addr: str) -> bytes:
    # only v4
    numbers = addr.split(".")
    assert len(numbers) == 4, "ERROR encoding invalid ipv4 address: {}".format(addr)
    r = b""
    for number in numbers:
        r += uint8(int(number))
    return r
