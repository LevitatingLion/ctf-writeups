# RSA Service

For this challenge we are provided with a python script running on a remote server. We can send it an RSA private key, the server will decrypt a fixed message using that key, and if the decrypted string matches another fixed string, it will send us the flag.

The private key can be parametrized by two of its components, the modulus `N` and the private exponent `d`, with the additional requirements that `N` must be the product of two primes and that `d` must be invertible in the ring of integers modulo `N` (the `key.check()` call makes sure these requirements are met for any key we send to the server).

For a given private exponent `d` we can compute a possible value for the modulus `N` that result in the correct decrypted message, by computing `diff = message ** d - target` and choosing any factor of the result as `N`. To satisfy the first requirement on the private key, we determine two large prime factors of `diff` and choose `N` as their product. If the second requirement is not met, the private exponent `d` was incorrect.

Now, all that's left to do is iterate over possible values for the private exponent `d` and try the method described above, until we find a pair `N`, `d` that meets all of our requirements. Then we dump the key in PEM format and send it to the server to get the flag.

Flag: `CSCG{下一家烤鴨店在哪裡？}`

Exploit script:

```py
from itertools import count

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers, RSAPublicNumbers
from factordb.factordb import FactorDB

message = 6453808645099481754496697330465
target = 1067267517149537754067764973523953846272152062302519819783794287703407438588906504446261381994947724460868747474504670998110717117637385810239484973100105019299532993569


def is_prime(n):
    f = FactorDB(n)
    f.connect()
    return f.get_status() in ("P", "Prp")

def get_primes(diff):
    f = FactorDB(diff)
    f.connect()

    factors = sorted(f.get_factor_list(), reverse=True)
    primes = []
    for fac in factors:
        if is_prime(fac):
            primes.append(fac)
            if len(primes) >= 2:
                break
    else:
        raise ValueError("No two prime factors found")

    return primes

# iterate over possible private exponents
for exp in count(6):
    print(exp)

    # target modulus, we choose a factor of this as the actual modulus
    diff = message ** exp - target

    try:
        # get two large prime factors
        p, q = get_primes(diff)

        # check that factors are large enough
        n = p * q
        if n <= target:
            continue

        # calculate key material
        d = exp
        e = pow(d, -1, (p - 1) * (q - 1))

        dmp1 = d % (p - 1)
        dmq1 = d % (q - 1)
        iqmp = pow(q, -1, p)

        # build and dump key
        priv = RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, RSAPublicNumbers(e, n))
        key = priv.private_key(default_backend())

        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        print(pem.decode())
        break

    except:
        pass
```

Running the script:

```sh
$ ./solve.py
6
7
8
[...]
95
96
97
-----BEGIN RSA PRIVATE KEY-----
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
ZSA=
-----END RSA PRIVATE KEY-----
```
