// AGPLv3 or later
// Copyright (c) 2015 Genome Research Limited

var assert     = require('assert'),
    xiongxiong = require('./index.js');

// Instantiation testing
(function() {
  // Needs at least one argument
  assert.throws(function() {
    var xx = xiongxiong();
  });
  
  // Needs privateKey property
  assert.throws(function() {
    var xx = xiongxiong({secretKey: 'foo'});
  });

  // Private key must be string or buffer
  assert.throws(function() {
    var xx = xiongxiong(123);
  });

  assert.doesNotThrow(function() {
    var xx = xiongxiong('foo');
  });

  assert.doesNotThrow(function() {
    var xx = xiongxiong(new Buffer('foo'));
  });

  // Unsupported hash algorithm
  assert.throws(function() {
    var xx = xiongxiong({privateKey: 'foo', algorithm: 'bar'});
  });
})();

// String seed
(function() {
  var xx      = xiongxiong('foo'),
      strSeed = 'foo bar';

  xx.encode(strSeed, function(err, t) {
    var token;

    // Shouldn't error
    assert.doesNotThrow(function() { throw err; });

    // Test bearer token
    token = xx.decode(t.accessToken);
    assert.equal(token.data, strSeed);
    assert.equal(token.valid, true);

    // Test auth pair
    token = xx.decode(t.basicLogin, t.basicPassword);
    assert.equal(token.data, strSeed);
    assert.equal(token.valid, true);
  });
})();

// Array seed
(function() {
  var xx      = xiongxiong('foo'),
      arrSeed = ['foo', 'bar'];

  xx.encode(arrSeed, function(err, t) {
    var token;

    // Shouldn't error
    assert.doesNotThrow(function() { throw err; });

    // Test bearer token
    token = xx.decode(t.accessToken);
    assert.deepEqual(token.data, arrSeed);
    assert.equal(token.valid, true);

    // Test auth pair
    token = xx.decode(t.basicLogin, t.basicPassword);
    assert.deepEqual(token.data, arrSeed);
    assert.equal(token.valid, true);
  });
})();

// Invalid seed
(function() {
  var xx      = xiongxiong('foo'),
      badSeed = 123;

  xx.encode(badSeed, function(err, t) {
    // Should error
    assert.throws(function() { throw err; });
  });
})();

// Expiration
(function() {
  var lifetime = parseInt((Math.random() * 3) + 3, 10),  // Lifetime between 3-5 seconds

      xx       = xiongxiong('foo', lifetime),
      seed     = 'foo bar',
      now      = new Date();

  xx.encode(seed, function(err, t) {
    var token;

    // Shouldn't error
    assert.doesNotThrow(function() { throw err; });

    // Token and expected expiration shouldn't differ by more than 1s
    token = xx.decode(t.accessToken);
    assert.ok(Math.abs((lifetime * 1000) - (token.expiration - now)) < 1000);
    assert.equal(token.valid, true);

    // Wait for lifetime + 1s, then we should have passed best before
    setTimeout(function() {
      assert.equal(token.valid, false);
    }, (lifetime + 1) * 1000);
  });
})();

// Legacy aliases
(function() {
  var xx      = xiongxiong('foo'),
      strSeed = 'foo bar';

  xx.create(strSeed, function(err, t) {
    var token;

    // Shouldn't error
    assert.doesNotThrow(function() { throw err; });

    // Test bearer token
    token = xx.extract(t.accessToken);
    assert.equal(token.data, strSeed);
    assert.equal(token.valid, true);

    // Test auth pair
    token = xx.extract(t.basicLogin, t.basicPassword);
    assert.equal(token.data, strSeed);
    assert.equal(token.valid, true);
  });
})();
