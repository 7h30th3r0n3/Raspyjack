
def RC4_encrypt(key, data):
    S = list(range(256))
    j = 0

    key_len = len(key)
    for i in list(range(256)):
        j = (j + S[i] + key[i % key_len]) % 256
        S[i], S[j] = S[j], S[i]

    j = 0
    y = 0
    out = []

    for char in data:
        j = (j + 1) % 256
        y = (y + S[j]) % 256
        S[j], S[y] = S[y], S[j]

        out.append(char ^ S[(S[j] + S[y]) % 256])

    return bytes(out)
