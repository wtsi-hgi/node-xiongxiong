'''
Test suite for Python decoder

AGPLv3 or later
Copyright (c) 2015 Genome Research Limited
'''

import json
from subprocess import Popen, PIPE
from datetime   import datetime
from xiongxiong import Xiongxiong


class Token(object):
  ''' Get token data to test against '''
  def __init__(self, data, privateKey, lifetime = 3600, algorithm = 'sha1'):
    jsonData = json.dumps(data);

    echo     = Popen(['echo', jsonData], stdout = PIPE)
    tokenise = Popen(['../getTestToken.js', privateKey, str(lifetime), algorithm],
                     stdin = echo.stdout, stdout = PIPE)

    output, err = tokenise.communicate()

    if tokenise.returncode == 0:
      output = json.loads(output)

      # Cast and set attributes of object
      self.expiration    = datetime.fromtimestamp(output['expiration'])
      self.accessToken   = str(output['accessToken'])
      self.basicLogin    = str(output['basicLogin'])
      self.basicPassword = str(output['basicPassword'])

    else:
      raise Exception(err)


def test(id, data, privateKey, basic = False, lifetime = 3600, algorithm = 'sha1'):
  ''' Generic testing function '''
  xiongxiong = Xiongxiong(privateKey, algorithm)
  encoded = Token(data, privateKey, lifetime, algorithm)

  if basic:
    decoded = xiongxiong(encoded.basicLogin, encoded.basicPassword)
  else:
    decoded = xiongxiong(encoded.accessToken)

  print('%s:' % id),

  try:
    assert decoded.valid, 'Token could not be validated'
    assert decoded.data == data, 'Decoded token data does not match'
    assert decoded.expiration == encoded.expiration, 'Token expiration does not match'
  
  except AssertionError as e:
    print('Failed - %s' % e.message)

  else:
    print('Passed')


# Tests
# TODO Failing tests; non-trivial key
test('String Data', 'foo bar', 'foo')
test('Array Data', ['foo', 'bar'], 'foo')
test('Basic Pair', 'foo bar', 'foo', basic = True)
test('Hash Algorithm', 'foo bar', 'foo', algorithm = 'md5')
test('Lifetime', 'foo bar', 'foo', lifetime = 100)
