import socket

from Crypto.Cipher import AES
from Crypto import Random

KEY_LENGTH = 16  # AES128
BLOCK_SIZE = AES.block_size

_random_gen = Random.new()
_key = _random_gen.read(KEY_LENGTH)

def _add_padding(msg):
    pad_len = BLOCK_SIZE - (len(msg) % BLOCK_SIZE)
    padding = bytes([pad_len]) * pad_len
    return msg + padding

def _remove_padding(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        return None
    for i in range(1, pad_len):
        if data[-i-1] != pad_len:
            return None
    return data[:-pad_len]

def encrypt(msg):
    iv = _random_gen.read(AES.block_size)
    cipher = AES.new(_key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(_add_padding(msg))

def _decrypt(data):
    iv = data[:BLOCK_SIZE]
    cipher = AES.new(_key, AES.MODE_CBC, iv)
    return _remove_padding(cipher.decrypt(data[BLOCK_SIZE:]))

def is_padding_ok(data):
    return _decrypt(data) is not None

if __name__ == '__main__'::
    # cleartext = b'"Don\'t allow your mind to tell your heart what to do. The mind gives up easily."'
    cleartext = b'For things to change, you have to change.'
    ciphertext = encrypt(cleartext)

    print("ciphertext:", ''.join(format(x, '02x').upper() for x in ciphertext))

    serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serv.bind(('0.0.0.0', 8080))
    serv.listen(5)
    while True:
    conn, addr = serv.accept()
    from_client = ''
    while True:
        data = conn.recv(4096)
        if not data: break
        from_client += data.decode('utf8')
        if (is_padding_ok(bytes.fromhex(from_client))):
            conn.send(b"Mac Error")
        else:
            conn.send(b"Padding Error")
    conn.close()
    print ('client disconnected and shutdown')
