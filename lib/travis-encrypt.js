var rsa = require('ursa');
var merge = require('lodash.merge');
var Travis = require('travis-ci');

var TOKEN = 'token';
var CREDS = 'creds';

function isUndefined (arg) {
  return typeof arg === 'undefined';
}

function encryptData (data, key, callback) {
  var pem = key.replace(/RSA PUBLIC KEY/g, 'PUBLIC KEY');
  try {
    var publicKey = rsa.createPublicKey(pem);
    var cipherText = publicKey.encrypt(data, undefined, undefined, rsa.RSA_PKCS1_PADDING);
    return callback(null, cipherText.toString('base64'));
  } catch (err) {
    return callback(err);
  }
}

function getTravisClient (pro) {
  return new Travis({
    version: '2.0.0',
    pro: pro
  });
}

function getRepoNotFoundError (options) {
  return new Error('repository ' + options.owner + '/' + options.repo + ' not found');
}

function encryptTravisProData (options, callback, type) {
  var travis = getTravisClient(true);

  if (type === CREDS) {
    travis.authenticate({
      username: options.username,
      password: options.password
    }, function onTravisAuthResponse (err) {
      if (err) {
        return callback(err);
      }

      getRepoKeyAndEncrypt(travis, options, callback);
    });
  } else {
    travis.auth.github.post({
      github_token: options.token
    }, function (err, res) {
      if (err) {
        return callback(err);
      }
      
      travis.authenticate({
        access_token: res.access_token
      }, function (err) {
        if (err) {
          return callback(err);
        }
        
        getRepoKeyAndEncrypt(travis, options, callback);
      });
    });
  }
}

function encryptTravisData (options, callback) {
  getRepoKeyAndEncrypt(getTravisClient(), options, callback);
}

function getRepoKeyAndEncrypt (client, options, callback) {
  client.repos(options.owner, options.repo).key.get(
    function onTravisRepoResponse (keyError, res) {      
      if (!keyError) {
        return encryptData(options.data, res.key, callback);
      }

      client.repos(options.owner, options.repo).get(
        function onKeylessTravisRepoResponse (reposError) {
          callback(reposError ? getRepoNotFoundError(options) : keyError);
        }
      );
    }
  );
}

function encrypt (options, callback) {
  if (typeof options.repo !== 'string') {
    return callback(new TypeError('`repo` must be a string'));
  } else if (!options.repo.match(/.\/./)) {
    return callback(new Error('`repo` must be in `owner/repo` form'));
  }

  if (typeof options.data !== 'string') {
    return callback(new TypeError('`data` must be a string'));
  }

  var hasUser = !isUndefined(options.username);
  var hasPass = !isUndefined(options.password);
  var hasToken = !isUndefined(options.token);

  if ((!hasUser && hasPass) || (hasUser && !hasPass)) {
    return callback(new Error('insufficient github credentials'));
  }

  var repo = options.repo.split('/', 2);
  var opts = merge(options, {
    owner: repo[0],
    repo: repo[1]
  });

  if ((hasUser && hasPass) || hasToken) {
    encryptTravisProData(opts, callback, hasToken ? TOKEN : CREDS);
  } else {
    encryptTravisData(opts, callback);
  }
}

module.exports = encrypt;
