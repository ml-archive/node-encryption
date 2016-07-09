import assert from 'assert'
import Crypt from '../src'

const crypt = new Crypt('%Td5lpaJzFO9fY#JXIfp7RA&&6qsVNw9');

describe('Crypt', () => {

	it('should encrypt then decrypt a string', () => {
		let string = 'a secret';
		let encrypted = crypt.encrypt(string);
		let decrypted = crypt.decrypt(encrypted);
		assert.equal(string, decrypted)
	});

	it('should encrypt then decrypt an object', () => {
		let obj = { some: 'secret', data: 'to encrypt' };
		let encrypted = crypt.encrypt(obj);
		let decrypted = crypt.decrypt(encrypted);
		assert.deepEqual(obj, decrypted)
	});

});
