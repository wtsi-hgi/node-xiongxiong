// Xiongxiong
// Bearer token generator and validator

// AGPLv3 or later
// Copyright (c) 2014 Genome Research Limited

var util   = require('util'),
    crypto = require('crypto');

module.exports = function(privateKey, lifetime) {
  lifetime = parseInt(lifetime || 3600, 10);

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
            var hmac       = crypto.createHmac('sha1', privateKey),
                expiration = Math.floor(Date.now() / 1000) + lifetime,
                message    = [data, salt.toString('base64')].join(':');
            
            // Generate SHA1 HMAC of user:expiration:session:salt
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

    validate: function(/* bearer/basic auth data */) {
      // TODO
    }
  };
};
