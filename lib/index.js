'use strict';

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _typeof2 = require('babel-runtime/helpers/typeof');

var _typeof3 = _interopRequireDefault(_typeof2);

var _stringify = require('babel-runtime/core-js/json/stringify');

var _stringify2 = _interopRequireDefault(_stringify);

var _classCallCheck2 = require('babel-runtime/helpers/classCallCheck');

var _classCallCheck3 = _interopRequireDefault(_classCallCheck2);

var _createClass2 = require('babel-runtime/helpers/createClass');

var _createClass3 = _interopRequireDefault(_createClass2);

var _crypto = require('crypto');

var _crypto2 = _interopRequireDefault(_crypto);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * You may encrypt a value using an Encryptor instance. All encrypted values are
 * encrypted using OpenSSL and the AES-256-CBC cipher (by default).
 *
 * All encrypted values are signed with a message authentication code (MAC) to
 * detect any modifications to the encrypted string.
 *
 * @version 1.0
 */

var Encryptor = function () {

	/**
  * Create a new Encryptor instance.
  *
  * @param {String} key      - Must be a 32 character length string, randomly generated.
  * @param {String} cipher   - Encryption algorithm.
  */

	function Encryptor(key) {
		var cipher = arguments.length <= 1 || arguments[1] === undefined ? 'aes-256-cbc' : arguments[1];
		(0, _classCallCheck3.default)(this, Encryptor);

		this.cipher = cipher;
		this.key = key;
	}

	/**
  * Get the initialization vector byte size.
  *
  * @returns {number}
  */


	(0, _createClass3.default)(Encryptor, [{
		key: 'encrypt',


		/**
   * Encrypt the given value. The value will be JSON encoded, so it can be an object, array, or string.
   *
   * @param {*} data
   *
   * @returns {String}
   */
		value: function encrypt(data) {

			var iv = _crypto2.default.randomBytes(this.ivSize);

			var Cipher = _crypto2.default.createCipheriv(this.cipher, this.key, iv);
			var encrypted = Cipher.update((0, _stringify2.default)(data), 'utf8', 'base64') + Cipher.final('base64');

			var result = {};
			result.iv = iv.toString('base64');
			result.value = encrypted;
			result.mac = this.hash(result.iv, result.value);

			return new Buffer((0, _stringify2.default)(result)).toString('base64');
		}

		/**
   * Decrypt the given value.
   *
   * @param {String} data
   *
   * @returns {String|Object|null}
   */

	}, {
		key: 'decrypt',
		value: function decrypt(data) {

			if (!data) {
				return null;
			}

			try {
				var payload = this.getJsonPayload(data);
				var iv = new Buffer(payload.iv, 'base64');

				var Decipher = _crypto2.default.createDecipheriv(this.cipher, this.key, iv);
				var decrypted = Decipher.update(payload.value, 'base64', 'utf8') + Decipher.final('utf8');

				return JSON.parse(decrypted);
			} catch (err) {

				return null;
			}
		}

		/**
   * Gets the payload object from the encryption string and verifies it's validity.
   *
   * @param {String} payload
   *
   * @returns {Object}
   */

	}, {
		key: 'getJsonPayload',
		value: function getJsonPayload(payload) {
			payload = JSON.parse(new Buffer(payload, 'base64').toString('ascii'));

			if (!payload || this.invalidPayload(payload)) {
				throw 'The payload is invalid.';
			}

			if (!this.validMac(payload)) {
				throw 'The MAC is invalid.';
			}

			return payload;
		}

		/**
   * Validate the Mac for the given payload.
   * This checks to make sure the data was not tampered with.
   *
   * @param {Object} payload
   *
   * @returns {boolean}
   *
   * @TODO Change to use Node's native method for time safe equality check when Node releases it.
   */

	}, {
		key: 'validMac',
		value: function validMac(payload) {

			var randBytes = _crypto2.default.randomBytes(16);

			var calcMac = _crypto2.default.createHmac('sha256', randBytes).update(this.hash(payload.iv, payload.value)).digest('hex');

			return timingSafeEquals(_crypto2.default.createHmac('sha256', randBytes).update(payload.mac).digest('hex'), calcMac);
		}

		/**
   * Verify the encryption payload is valid.
   *
   * @param {Object} payload
   *
   * @return bool
   */

	}, {
		key: 'invalidPayload',
		value: function invalidPayload(payload) {
			return (typeof payload === 'undefined' ? 'undefined' : (0, _typeof3.default)(payload)) !== 'object' || !payload.hasOwnProperty('iv') || !payload.hasOwnProperty('value') || !payload.hasOwnProperty('mac');
		}

		/**
   * Create a MAC for the given value.
   *
   * @param {string} iv
   * @param {string} value
   *
   * @return string
   */

	}, {
		key: 'hash',
		value: function hash(iv, value) {
			return _crypto2.default.createHmac('sha256', this.key).update(iv + value).digest('hex');
		}
	}, {
		key: 'ivSize',
		get: function get() {
			return 16;
		}
	}]);
	return Encryptor;
}(); /**
      * @file Encryptor
      * @module Encryptor
      * @author Kirill Fuchs <kirill.fuchs@gmail.com>
      */

exports.default = Encryptor;

/**
 * Time safe string comparison.
 *
 * Note: this will be obsolete with the introduction of a method in the Crypto library.
 * @see https://github.com/nodejs/node/issues/3043
 *
 * @param {string} hmacOne
 * @param {string} hmacTwo
 *
 * @returns {boolean}
 */

function timingSafeEquals(hmacOne, hmacTwo) {

	if (hmacOne.length !== hmacTwo.length) {
		return false;
	}

	var zero = 0;
	for (var i = 0; i < hmacOne.length; i++) {
		zero |= hmacOne.charCodeAt(i) ^ hmacTwo.charCodeAt(i);
	}

	return zero === 0;
}