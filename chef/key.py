import six

import rsa

class SSLError(Exception):
    """An error in OpenSSL."""

    def __init__(self, message, *args):
        message = message%args
        super(SSLError, self).__init__(message)


class Key(object):
    """An RSA key handler"""

    def __init__(self, fp=None):
        self.key = None
        self.public = False
        if not fp:
            return
        if isinstance(fp, six.binary_type) and fp.startswith(b'-----BEGIN'):
            # PEM formatted text
            self.raw = fp
        elif isinstance(fp, six.string_types) and fp.startswith('-----BEGIN'):
            # PEM formatted text
            self.raw = fp
        elif isinstance(fp, six.string_types):
            self.raw = open(fp, 'rb').read()
        else:
            self.raw = fp.read()
        self._load_key()

    def _load_key(self):
        try:
            self.key = rsa.PrivateKey.load_pkcs1(self.raw)
        except ValueError:
            self.key = rsa.PublicKey.load_pkcs1(self.raw)
            self.public = True
        except:
            raise ValueError("'{}' is not a valid RSA key".format(self.raw))

    @classmethod
    def generate(cls, size=1024):
        self = cls()
        (_, self.key) = rsa.newkeys(size)
        return self

    def sign(self, message):
        """ Simplified signature compatible with `openssl rsautl -sign`
        
        Signing logic pulled from the rsa lib, but does not add the asn1 before padding.

        """

        if self.public:
            raise SSLError('can not sign a message using a public key')

        keylength = rsa.common.byte_size(self.key.n)
        padded = rsa.pkcs1._pad_for_signing(message, keylength)
        payload = rsa.transform.bytes2int(padded)
        encrypted = rsa.core.encrypt_int(payload, self.key.d, self.key.n)
        block = rsa.transform.int2bytes(encrypted, keylength)
        return block

    def verify(self, message, sig):
        """ Emulate `openssl rsautl -verify` """

        blocksize = rsa.common.byte_size(self.key.n)
        encrypted = rsa.transform.bytes2int(sig)
        decrypted = rsa.core.decrypt_int(encrypted, self.key.e, self.key.n)
        clearsig = rsa.transform.int2bytes(decrypted, blocksize)

        # If we can't find the signature  marker, verification failed.
        if clearsig[0:2] != '\x00\x01':
            raise VerificationError('Verification failed')

        padded = rsa.pkcs1._pad_for_signing(message, blocksize)
        if padded != clearsig:
            raise VerificationError('Verification failed')

        return True

    def encrypt(self, message):
        return rsa.encrypt(message, self.key)

    def decrypt(self, message):
        return rsa.decrypt(message, self.key)

    def private_export(self):
        if self.public:
            raise SSLError('private method cannot be used on a public key')

        return self.key.save_pkcs1('PEM')

    def public_export(self):
        return rsa.PublicKey(self.key.n, self.key.e).save_pkcs1('PEM')


