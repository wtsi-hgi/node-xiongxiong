'''
Xiongxiong Bearer Token Decoder for Python

AGPLv3 or later
Copyright (c) 2015 Genome Research Limited
'''

from datetime import datetime
import base64
import hashlib
import hmac

def stfu(fn):
  ''' Decorator to silence fussy string functions '''
  def wrapper(*args, **kwargs):
    try:
      return fn(*args, **kwargs)
    except:
      return ''
  return wrapper

@stfu
def b64encode(this):
  ''' Base64 encode '''
  return base64.b64encode(this)

@stfu
def b64decode(this):
  ''' Base64 decode '''
  return base64.b64decode(this)


class Token(object):
  '''
  Return type from token decoder
  n.b., This shouldn't be instantiated directly 
  '''

  def __init__(self, authenticated):
    if authenticated:
      self.data       = authenticated['data']
      self.expiration = authenticated['expiration']

    else:
      self.data       = None
      self.expiration = None

  # Override getters to give us a nicer syntax
  def __getattribute__(self, name):
    allowed = ['data', 'expiration']
    actual  = {}

    # Actual object properties
    for key in allowed:
      actual[key] = object.__getattribute__(self, key)

    if name == 'valid':
      if actual['expiration']:
        # Validity is contingent upon expiration
        return datetime.now() <= actual['expiration']

      else:
        # Not cool
        return False

    elif name in allowed:
      return actual[name]

    else:
      raise AttributeError


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
      from external access (say, if it were a public class member)
      '''
      secureHash = getattr(hashlib, algorithm)
      authCode   = hmac.new(privateKey, message, secureHash)
      return b64encode(authCode.digest())

    self._getHMAC = getHMAC

  def __call__(self, *args):
    ''' Decode the bearer token/basic authentication pair '''

    if len(args) == 1:
      # Split bearer token and decode as basic auth
      accessToken = b64decode(args[0]).split(':')

      basicPassword = accessToken.pop()
      basicLogin    = b64encode(':'.join(accessToken))

      return self(basicLogin, basicPassword)

    elif len(args) == 2:
      # Basic authentication pair
      basicLogin    = b64decode(args[0])
      extracted     = basicLogin.split(':')
      basicPassword = args[1]
      
      # Pass the salt
      extracted.pop()

      # Validity check
      if basicPassword == self._getHMAC(basicLogin):
        # We're good!
        return Token({
          'expiration': datetime.fromtimestamp(int(extracted.pop())),
          'data':       extracted[0] if len(extracted) == 1 else extracted
        })

      else:
        # Epic fail
        return Token(None)

    else:
      # WTF?
      raise Exception('Invalid arguments')


# Our module shouldn't run standalone
if __name__ == '__main__':
  import sys
  print('Xiongxiong decoder shouldn\'t run standalone:')
  print('>>> from xiongxiong import Xiongxiong')
  sys.exit(1)
