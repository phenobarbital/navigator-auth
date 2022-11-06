# cython: language_level=3, embedsignature=True, boundscheck=False, wraparound=True, initializedcheck=False
# Copyright (C) 2018-present Jesus Lara
#
import base64
import codecs
from Crypto import Random
from Crypto.Cipher import AES
from rncryptor import DecryptionError, RNCryptor
from libcpp cimport bool as bool_t

## TODO: migrate to cython
cdef class Cipher:
    """Can Encode/Decode a string using AES-256 or RNCryptor."""
    cdef int BS
    cdef bool_t base64encoded
    cdef object key
    cdef str _type
    cdef bytes iv
    cdef object cipher

    def __init__(self, object key, str type = 'AES', bool_t b64encoded = False):
        self.key = key
        self._type = type
        self.base64encoded = b64encoded
        self.BS = 16
        if type == 'AES':
            self.iv = Random.new().read(AES.block_size)
            self.cipher = AES.new(self.key.encode('utf-8'), AES.MODE_CFB, self.iv)
        elif type == "RNC":
            self.cipher = RNCryptor()
            self.iv = b""
        else:
            raise NotImplementedError(
                f"Error: Cypher {type} not implemented."
            )

    cpdef str encode(self, str message):
        return self._encode(message)

    cpdef str _encode(self, str message):
        if self._type == "AES":
            msg = self.iv + self.cipher.encrypt(
                message.encode("utf-8")
            )
        elif self._type == "RNC":
            msg = self.cipher.encrypt(
                message, self.key
            )
            if self.base64encoded:
                msg = base64.b64encode(msg)
        else:
            return ""
        if msg:
            return codecs.encode(msg, "hex").decode("utf-8")

    cpdef str decode(self, object passphrase):
        return self._decode(passphrase)

    cdef str _decode(self, object passphrase):
        msg = codecs.decode(passphrase, "hex")
        if self._type == "AES":
            try:
                return self.cipher.decrypt(
                    msg
                )[len(self.iv) :].decode("utf-8")
            except Exception as e:
                raise
        elif self._type == "RNC":
            try:
                msg = self.cipher.decrypt(
                    msg,
                    self.key
                )
                if self.base64encoded:
                    return base64.b64decode(msg, validate=True)
                else:
                    return msg
            except DecryptionError as ex:
                raise ValueError(
                    f"RNC Error: decoding passhprase: {ex}"
                )
            except Exception:
                raise
