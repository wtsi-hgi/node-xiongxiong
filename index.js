// Xiongxiong
// Bearer token codec

// AGPLv3 or later
// Copyright (c) 2014, 2015 Genome Research Limited

var util   = require('util'),
    crypto = require('crypto');

module.exports = function(/* privateKey, lifetime, algorithm OR hash */) {
  var privateKey, lifetime, algorithm;

  // Parse arguments
  if (arguments.length) {
    // Try to get options from hash first, then fallback to positional
    // and finally, where appropriate, to defaults
    privateKey = arguments[0].privateKey        || arguments[0];
    lifetime   = parseInt(arguments[0].lifetime || arguments[1], 10) || 3600;
    algorithm  = arguments[0].algorithm         || arguments[2]      || 'sha1';

    // Private key must be a string or a buffer
    if (!(typeof privateKey == 'string' || privateKey instanceof Buffer)) {
      throw new TypeError('Invalid arguments: Private key must be a string or buffer');
    }
  } else {
    // Need at least a private key  
    throw new Error('No private key specified');
  }

  var getHMAC = (function() {
    // Check algorithm is supported
    if (crypto.getHashes().indexOf(algorithm) < 0) {
      throw new Error('Unsupported hash algorithm \'' + algorithm + '\'');
    }

    return function(message) {
      var hmac = crypto.createHmac(algorithm, privateKey);
      hmac.setEncoding('base64');
      hmac.end(message);
      return hmac.read();
    };
  })();

  return {
    create: function(data, callback) {
      // Flatten array
      if (util.isArray(data)) { data = data.join(':'); }

      if (typeof data != 'string') {
        callback(new TypeError('Invalid arguments: Seed data must be a string or array of strings'), null);

      } else {
        // Create a 48-bit salt
        crypto.randomBytes(6, function(err, salt) {
          if (err) {
            callback(err, null);
          
          } else {
            var expiration = Math.floor(Date.now() / 1000) + lifetime,
                message    = [data, expiration, salt.toString('base64')].join(':'),

                // Generate HMAC of data:expiration:salt
                password   = getHMAC(message);
            
            // Return token and basic authentication pair
            callback(null, {
              expiration:    expiration,  // Unix epoch
              accessToken:   (new Buffer([message, password].join(':'))).toString('base64'),
              basicLogin:    (new Buffer(message)).toString('base64'),
              basicPassword: password
            });
          }
        });
      }
    },

    extract: function(/* bearer/basic auth data */) {
      var output = {isValid: false};

      switch (arguments.length) {
        case 1:
          // Split bearer token and extract as basic auth
          var accessToken = (new Buffer(arguments[0], 'base64')).toString().split(':');

          var basicPassword = accessToken.pop(),
              basicLogin    = (new Buffer(accessToken.join(':'))).toString('base64');

          output = this.extract(basicLogin, basicPassword);

          break;

        case 2:
          // Basic authentication data
          var basicLogin    = (new Buffer(arguments[0], 'base64')).toString(),
              extracted     = basicLogin.split(':'),
              basicPassword = arguments[1];

          // Pass the salt
          extracted.pop();

          output = {
            // Expiration is penultimate element
            // n.b., JavaScript Date in ms, hence x1000 on Unix epoch
            expiration: new Date(parseInt(extracted.pop(), 10) * 1000),

            // Convert to string if we only have one element remaining
            data: extracted.length == 1 ? extracted[0] : extracted,

            // Validity check
            isValid: (function() {
              if (basicPassword == getHMAC(basicLogin)) {
                return function() {
                  // Match: Valid until expiration
                  return Date.now() <= this.expiration;
                };

              } else {
                // No match: Invalid
                return function() { return false; }
              }
            })()
          };

          break;

        default:
          break;
      }

      return output;
    }
  };
};
