#!/usr/bin/env node

// Generate token data to test the decoders
// Reads JSON (string/array of strings) from stdin, output JSON to stdout

// Usage:
// getTestToken.js KEY [LIFETIME] [ALGORITHM]

// AGPLv3 or later
// Copyright (c) 2015 Genome Research Limited

var options = (function(argv) {
  var output = {};

  // Get private key from first argument
  // Prefer reading from filesystem than explicitly specifying
  if (argv[0]) {
    var fs = require('fs');
    if (fs.existsSync(argv[0])) {
      output.privateKey = fs.readFileSync(argv[0]);
    } else {
      output.privateKey = argv[0]
    }
  } else {
    console.error('No private key specified');
    process.exit(1);
  }

  // Get lifetime from second argument (optional)
  if (argv[1]) {
    output.lifetime = parseInt(argv[1], 10) || 3600;
  }

  // Get algorithm from third argument (optional)
  if (argv[2]) {
    var crypto = require('crypto');
    if (crypto.getHashes().indexOf(argv[2]) >= 0) {
      output.algorithm = argv[2];
    }
  }

  return output;
})(process.argv.slice(2));

var xiongxiong = require('../')(options),
    input      = '';

process.stdin
  .setEncoding('utf8')

  // Read and append data chunks from stdin into input buffer
  .on('readable', function() {
    var chunk = process.stdin.read();

    if (chunk !== null) {
      input += chunk;
    }
  })

  // Type check input buffer and encode
  .on('end', function() {
    var data,
        isString = function(a) { return typeof a == 'string'; };

    // Only accept JSON input
    try {
      data = JSON.parse(input.trim());
    }
    catch(err) {
      console.error(err.message);
      process.exit(1);
    }

    // Check we have a string or an array of strings
    if (isString(data) || (Array.isArray(data) && data.every(isString))) {
      xiongxiong.encode(data, function(err, token) {
        if (err) {
          console.error(err.message);
          process.exit(1);

        } else {
          // Finally!
          console.log(JSON.stringify(token));
        }
      });

    } else {
      console.error('Input data must be a string or an array of strings');
      process.exit(1);
    }
  });
