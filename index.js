// Xiongxiong
// Bearer token generator and validator

// AGPLv3 or later
// Copyright (c) 2014 Genome Research Limited

var util   = require('util'),
    crypto = require('crypto');

module.exports = function(privateKey, lifetime) {
  lifetime = parseInt(lifetime || 3600, 10);
  var getHMAC = function() { return crypto.createHmac('sha1', privateKey); };

  return {
    create: function(data, callback) {
      // Flatten array
      if (util.isArray(data)) { data = data.join(':'); }

      if (typeof(data) != 'string') {
        callback(new TypeError('Seed data must be a string or array of strings'), null);

      } else {
        // Create a 48-bit salt
        crypto.randomBytes(6, function(err, salt) {
          if (err) {
            callback(err, null);
          
          } else {
            var hmac       = getHMAC(),
                expiration = Math.floor(Date.now() / 1000) + lifetime,
                message    = [data, expiration, salt.toString('base64')].join(':');
            
            // Generate SHA1 HMAC of data:expiration:salt
            hmac.setEncoding('base64');
            hmac.end(message);
            var password = hmac.read();

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

    isValid: function(/* bearer/basic auth data */) {
      var valid = false;

      switch (arguments.length) {
        case 1:
          // Split bearer token and validate as basic auth
          var accessToken = (new Buffer(arguments[0], 'base64')).toString().split(':');

          var basicPassword = accessToken.pop(),
              basicLogin    = (new Buffer(accessToken.join(':'))).toString('base64');

          valid = this.isValid(basicLogin, basicPassword);

          break;

        case 2:
          // Basic authentication
          var basicLogin    = (new Buffer(arguments[0], 'base64')).toString(),
              extracted     = basicLogin.split(':'),
              basicPassword = arguments[1];

          // Expiration is penultimate element
          // n.b., JavaScript Date in ms, hence x1000 on Unix epoch
          var expiration = parseInt(extracted.slice(-2, -1)[0], 10) * 1000;

          if (Date.now() > expiration) {
            // Expired
            valid = false;
          
          } else {
            var hmac = getHMAC();

            // Generate SHA1 HMAC of basicLogin to check against
            hmac.setEncoding('base64');
            hmac.end(basicLogin);

            valid = (basicPassword == hmac.read());
          }

          break;

        default:
          break;
      }

      return valid;
    }
  };
};
