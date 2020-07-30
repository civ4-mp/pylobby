# 6 procedures related to encoding in GP
# Sources: GSOpenSDK, aluigi's works, PRMasterserver
import base64
import hashlib


def pw_decode_hash(pw_encoded: str) -> str:
    md5 = hashlib.md5()
    md5.update(_pw_decode_f0(pw_encoded))
    return md5.hexdigest()


def _pw_decode_f0(pw_encoded: str) -> bytes:
    pwencx = base64.b64decode(
        pw_encoded.replace("[", "+").replace("]", "/").replace("_", "=")
    )
    return _pw_decode_f1(pwencx)


def _pw_decode_f1(pwencx: bytes) -> bytes:
    num = 2037412711
    for i in range(0, len(pwencx)):
        num = _pw_decode_f2(num)
        a = num % 255
        pwencx = pwencx[:i] + bytes([pwencx[i] ^ a]) + pwencx[i + 1 :]
    return pwencx


def _pw_decode_f2(num: int) -> int:
    c = (num >> 16) & 65535
    a = num & 65535
    c *= 16807
    a *= 16807
    a += (c & 32767) << 16
    if a >= 2147483648:
        a += -4294967296
    if a < 0:
        a &= 2147483647
        a += 1
    a += c >> 15
    if a < 0:
        a &= 2147483647
        a += 1
    return a


def pw_hash_to_response(pwhash: str, unick: str, schal: str, cchal: str) -> str:
    md5 = hashlib.md5()
    mix = pwhash + (" " * 48) + unick + cchal + schal + pwhash
    md5.update(mix.encode("windows-1253", "ignore"))
    return md5.hexdigest()


def pw_hash_to_proof(pwhash: str, unick: str, schal: str, cchal: str) -> str:
    md5 = hashlib.md5()
    mix = pwhash + (" " * 48) + unick + schal + cchal + pwhash
    md5.update(mix.encode("windows-1253", "ignore"))
    return md5.hexdigest()
