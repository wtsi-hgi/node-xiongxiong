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

Obviously, the private key and hashing algorithm must match those used
by the encoder.

### `xiongxiong(accessToken)`
### `xiongxiong(basicLogin, basicPassword)`

Decode the seed data, expiration and validate from the bearer
token/basic authentication pair. Returns a `Token` object (see below).

## `Token` Class

As instantiation of this class is returned by the decoding function (it
shouldn't be instantiated directly, so there's no need to `import` it).
It has the following members:

* `.data` The original seed data, which will be split into a list by `:`
  characters, wherever possible (a string, otherwise).
* `.expiration` The expiration time (`datetime.datetime`)
* `.valid` The validity of the token/basic pair (Boolean).

For example:

```python
from datetime import datetime

tokenData = xiongxiong(someBearerToken)

if tokenData.valid:
  expiresIn = tokenData.expiration - datetime.now()
  print('Token expires in %d seconds.' % expiresIn.seconds)
```

The validity property (`valid`) will return `false` if the token can't
be authenticated, otherwise it will test whether the token has passed
its best before date.

*TODO* Make the `data` and `expiration` properties read-only.
