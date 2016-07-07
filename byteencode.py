def uint16(number):
    number = int(number)
    assert 0 <= number < 2 ** 16, "ERROR encoding invalid uint16: {}".format(number)
    (high, low) = divmod(number, 256)
    return bytearray([high, low])


def uint8(number):
    number = int(number)
    assert 0 <= number < 256, "ERROR encoding invalid uint8: {}".format(number)
    return bytearray([number])

def ipaddr(addr):
    # only v4
    numbers = addr.split('.')
    assert len(numbers) == 4, "ERROR encoding invalid ipv4 address: {}".format(addr)
    r = bytearray()
    for number in numbers:
        i = int(number)
        assert 0 <= i < 256, "ERROR encoding invalid ipv4 address: {}".format(addr)
        r += bytearray([i])
    return r
