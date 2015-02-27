'''
Minimal testing harness for Python decoder
This is NOT a full test suite

AGPLv3 or later
Copyright (c) 2015 Genome Research Limited
'''

import json
from subprocess import Popen, PIPE
from datetime   import datetime
from xiongxiong import Xiongxiong

def getToken(data, privateKey):
  js = '''
  var xiongxiong = require('../../')('%s');

  xiongxiong.encode(%s, function(err, token) {
    console.log(token.accessToken);
  });
  ''' % (privateKey, json.dumps(data))

  echo = Popen(['echo', js], stdout = PIPE)
  node = Popen('node', stdin = echo.stdout, stdout = PIPE)

  return node.communicate()[0].strip()

data = ['Hello', 'World!']
key  = 'abc123'

token = getToken(data, key)
xiongxiong = Xiongxiong(key)

decoded = xiongxiong(token)

if decoded.valid:
  print('Passed: %s' % (decoded.data == data))

  expiresIn = decoded.expiration - datetime.now()
  print('Data:   %s' % decoded.data)
  print('Expiry: T-%d seconds' % expiresIn.seconds)

else:
  print('Passed: False')
