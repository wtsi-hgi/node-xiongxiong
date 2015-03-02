'''
Xiongxiong Bearer Token Decoder for Python

AGPLv3 or later
Copyright (c) 2015 Genome Research Limited
'''

from datetime import datetime
import base64
import hashlib
import hmac


def _stfu(fn):
  ''' Decorator to silence fussy string functions '''
  def wrapper(*args, **kwargs):
    try:
      return fn(*args, **kwargs)
    except:
      return ''
  return wrapper

@_stfu
def _b64encode(this):
  ''' Base64 encode '''
  return base64.b64encode(this)

@_stfu
def _b64decode(this):
  ''' Base64 decode '''
  return base64.b64decode(this)


def _tokenFactory(authenticated):
  '''
  Build a Token class, based upon the function arguments in the closure,
  and return an instantiation of it. This allows us return an object
  with truly read-only properties :) These 'hoops' suggest that this is
  probably 'unpythonic', but what can you do?!

  n.b., This shouldn't be invoked directly.
  '''

  if not authenticated:
    weAreGood = False
    authenticated = { 'data': None, 'expiration': None }

  else:
    weAreGood = True

  class Token(object):
    def __getattribute__(self, name):
      ''' Fake attributes '''
      if name == 'valid':
        if weAreGood:
          return datetime.now() <= authenticated['expiration']

        else:
          return False

      if name in authenticated:
        return authenticated[name]

      else:
        # No such attribute
        raise AttributeError

    def __setattr__(self, value, name):
      ''' We can't set any attribute values '''
      raise AttributeError

  return Token()


class Xiongxiong(object):
  '''
  Bearer token decoder
  Instantiate with a private key and optional hash algorithm
  '''

  def __init__(self, privateKey, algorithm = 'sha1'):
    # Check algorithm is supported
    try:
      # >= 2.7.9
      available = hashlib.algorithms_available
    except:
      # >= 2.7
      available = hashlib.algorithms

    if algorithm not in available:
      raise Exception('Unsupported hash algorithm \'%s\'' % algorithm)

    def getHMAC(message):
      '''
      Create HMAC of message using the instantiation private key and
      hashing algorithm. This is created as a closure to protect the key
      from external access (say, if it were a class member)
      '''
      secureHash = getattr(hashlib, algorithm)
      authCode   = hmac.new(privateKey, message, secureHash)
      return _b64encode(authCode.digest())

    self.__getHMAC = getHMAC

  def __call__(self, *args):
    ''' Decode the bearer token/basic authentication pair '''

    if len(args) == 1:
      # Split bearer token and decode as basic auth
      accessToken = _b64decode(args[0]).split(':')

      basicPassword = accessToken.pop()
      basicLogin    = _b64encode(':'.join(accessToken))

      return self(basicLogin, basicPassword)

    elif len(args) == 2:
      # Basic authentication pair
      basicLogin    = _b64decode(args[0])
      extracted     = basicLogin.split(':')
      basicPassword = args[1]
      
      # Pass the salt
      extracted.pop()

      # Validity check
      if basicPassword == self.__getHMAC(basicLogin):
        # We're good!
        return _tokenFactory({
          'expiration': datetime.fromtimestamp(int(extracted.pop())),
          'data':       extracted[0] if len(extracted) == 1 else extracted
        })

      else:
        # Epic fail
        return _tokenFactory(None)

    else:
      # WTF?
      raise Exception('Invalid arguments')


# Our module shouldn't run standalone
if __name__ == '__main__':
  import sys
  print('Xiongxiong decoder shouldn\'t run standalone:')
  print('>>> from xiongxiong import Xiongxiong')
  sys.exit(1)
