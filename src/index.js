/**
 * @file Encryptor
 * @module Encryptor
 * @author Kirill Fuchs <kirill.fuchs@gmail.com>
 */


import Crypto from 'crypto';


/**
 * You may encrypt a value using an Encryptor instance. All encrypted values are
 * encrypted using OpenSSL and the AES-256-CBC cipher (by default).
 *
 * All encrypted values are signed with a message authentication code (MAC) to
 * detect any modifications to the encrypted string.
 *
 * @version 1.0
 */
class Encryptor {

	/**
	 * Create a new Encryptor instance.
	 *
	 * @param {String} key      - Must be a 32 character length string, randomly generated.
	 * @param {String} cipher   - Encryption algorithm.
	 */
	constructor(key, cipher = 'aes-256-cbc') {
		this.cipher = cipher;
		this.key = key;
	}

	/**
	 * Get the initialization vector byte size.
	 *
	 * @returns {number}
	 */
	get ivSize() {
		return 16;
	}

	/**
	 * Encrypt the given value. The value will be JSON encoded, so it can be an object, array, or string.
	 *
	 * @param {*} data
	 *
	 * @returns {String}
	 */
	encrypt(data) {

		let iv = Crypto.randomBytes(this.ivSize);

		let Cipher = Crypto.createCipheriv(this.cipher, this.key, iv);
		let encrypted = Cipher.update(JSON.stringify(data), 'utf8', 'base64') + Cipher.final('base64');

		let result = {};
		result.iv = iv.toString('base64');
		result.value = encrypted;
		result.mac = this.hash(result.iv, result.value);

		return (new Buffer(JSON.stringify(result))).toString('base64');
	}

	/**
	 * Decrypt the given value.
	 *
	 * @param {String} data
	 *
	 * @returns {String|Object|null}
	 */
	decrypt(data) {

		if (! data) {
			return null;
		}

		try {
			let payload = this.getJsonPayload(data);
			let iv = new Buffer(payload.iv, 'base64');

			let Decipher = Crypto.createDecipheriv(this.cipher, this.key, iv);
			let decrypted = Decipher.update(payload.value, 'base64', 'utf8') + Decipher.final('utf8');

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
	getJsonPayload(payload) {
		payload = JSON.parse((new Buffer(payload, 'base64')).toString('ascii'));

		if (! payload || this.invalidPayload(payload)) {
			throw 'The payload is invalid.';
		}

		if (! this.validMac(payload)) {
			throw 'The MAC is invalid.'
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
	validMac(payload) {

		let randBytes = Crypto.randomBytes(16);

		let calcMac = Crypto.createHmac('sha256', randBytes).update(this.hash(payload.iv, payload.value)).digest('hex');

		return timingSafeEquals(
			Crypto.createHmac('sha256', randBytes).update(payload.mac).digest('hex'),
			calcMac
		);

	}

	/**
	 * Verify the encryption payload is valid.
	 *
	 * @param {Object} payload
	 *
	 * @return bool
	 */
	invalidPayload(payload) {
		return (typeof payload !== 'object'
		|| ! payload.hasOwnProperty('iv')
		|| ! payload.hasOwnProperty('value')
		|| ! payload.hasOwnProperty('mac'));
	}

	/**
	 * Create a MAC for the given value.
	 *
	 * @param {string} iv
	 * @param {string} value
	 *
	 * @return string
	 */
	hash(iv, value) {
		return Crypto.createHmac('sha256', this.key).update(iv + value).digest('hex');
	}
}


export default Encryptor;


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

	let zero = 0;
	for (let i = 0; i < hmacOne.length; i++) {
		zero |= hmacOne.charCodeAt(i) ^ hmacTwo.charCodeAt(i);
	}

	return zero === 0;
}
