'''
Xiongxiong Bearer Token Decoder for Python

AGPLv3 or later
Copyright (c) 2015 Genome Research Limited
'''

from datetime import datetime
from base64   import b64encode, b64decode
import hashlib
import hmac

def silence(fallback = None):
  ''' Decorator to silence fussy functions that complain too much '''
  def wrapper(fn):
    def _(*args, **kwargs):
      try:
        return fn(*args, **kwargs)
      except:
        return fallback
    return _
  return wrapper

@silence()
def encode(this):
  ''' Base64 encode '''
  return b64encode(this)

@silence()
def decode(this):
  ''' Base64 decode '''
  return b64decode(this)

# n.b., This could just as well be a dictionary, rather than a class,
# but this way seems a bit clearer...
class _Token(object):
  '''
  Return type from token decoding. This shouldn't be used directly. 
  '''

  def __init__(self, authenticated = False):
    if authenticated:
      self.data       = authenticated['data']
      self.expiration = authenticated['expiration']

      # Validity is contingent upon expiration
      self.isValid = lambda: datetime.now() <= self.expiration

    else:
      self.data       = None
      self.expiration = None

      # Not cool
      self.isValid = lambda: False

class Xiongxiong(object):
  '''
  Bearer token decoder; instantiate with a private key and optional hash
  algorithm (defaults to sha1)
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
      return encode(authCode.digest())

    self._getHMAC = getHMAC

  @silence(_Token(False))
  def decode(self, *args):
    ''' Decode the bearer token/basic authentication pair '''

    if len(args) == 1:
      # Split bearer token and decode as basic auth
      accessToken = decode(args[0]).split(':')

      basicPassword = accessToken.pop()
      basicLogin    = encode(':'.join(accessToken))

      return self.decode(basicLogin, basicPassword)

    elif len(args) == 2:
      # Basic authentication pair
      basicLogin    = decode(args[0])
      extracted     = basicLogin.split(':')
      basicPassword = args[1]
      
      # Pass the salt
      extracted.pop()

      # Validity check
      if basicPassword == self._getHMAC(basicLogin):
        # We're good!
        return _Token({
          'expiration': datetime.fromtimestamp(int(extracted.pop())),
          'data':       extracted[0] if len(extracted) == 1 else extracted
        })

      else:
        # Epic fail
        raise Exception('Cannot authenticate')

    else:
      # WTF?
      raise Exception('Invalid arguments')

# Our module shouldn't run standalone
if __name__ == '__main__':
  import sys
  print('Xiongxiong decoder shouldn\'t run standalone:')
  print('>>> from xiongxiong import Xiongxiong')
  sys.exit(1)
