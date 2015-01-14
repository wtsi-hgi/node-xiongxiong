# Xiongxiong Decoder

Bearer token decoder for Python (>= 2.7).

## `Xiongxiong` Class

The class *must* be instantiated with the private key and, optionally,
the hashing algorithm (defaults to `sha1`).

For example:

```python
from xiongxiong import Xiongxiong
xiongxiong = Xiongxiong(privateKey, 'md5')
```

n.b., An exception will be thrown if the specified hashing algorithm is
not supported. If you are using Python 2.7.9, or later, you will have
access to all the algorithms supported by your platform's instance of
OpenSSL; otherwise you are limited to MD5, SHA1, SHA224, SHA256, SHA384
and SHA512.

### `.decode(accessToken)`
### `.decode(basicLogin, basicPassword)`

Decode the seed data, expiration and validate from the bearer
token/basic authentication pair. Returns a `_Token` object (see below).

## `_Token` Class

This class is returned by the decoding function and shouldn't be used
directly. Its members are, however, important:

* `.data` The original seed data, which will be an array split by `:`
  characters, wherever possible (a string, otherwise).
* `.expiration` The expiration time (`datetime.datetime`)
* `.isValid()` The validity of the token/basic pair (function).

For example:

```python
from datetime import datetime

tokenData = xiongxiong.decode(someBearerToken)

if tokenData.isValid():
  expiresIn = tokenData.expiration - datetime.now()
  print('Token expires in %d seconds.' % expiresIn.seconds)
```
