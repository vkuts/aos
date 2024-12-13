import { test } from 'node:test'
import * as assert from 'node:assert'
import AoLoader from '@permaweb/ao-loader'
import fs from 'fs'

const wasm = fs.readFileSync('./process.wasm')
const options = {
	format: "wasm64-unknown-emscripten-draft_2024_02_15",
 }

 test('Return the value of secp256k1.p', async () => {
  const handle = await AoLoader(wasm, options);
	const env = {
		Process: {
			Id: 'AOS',
			Owner: 'FOOBAR',
			Tags: [{ name: 'Name', value: 'Thomas' }],
		},
	};

	const data = `
		local es256k = require ".es256k"
		return tostring(es256k.secp256k1.p)
	`;
	
	const msg = {
		Target: 'AOS',
		From: 'FOOBAR',
		Owner: 'FOOBAR',
		['Block-Height']: '1000',
		Id: '1234xyxfoo',
		Module: 'WOOPAWOOPA',
		Tags: [{ name: 'Action', value: 'Eval' }],
		Data: data,
	};

	const result = await handle(null, msg, env);

	console.log('Error:', result.Error, ", Result: ", result.Output?.data)
  assert.equal(result.Error, undefined)
  assert.equal(result.Output?.data, "115792089237316195423570985008687907853269984665640564039457584007908834671663")
  assert.ok(true)
})

test('Calculate a square root of a bigint', async () => {
  const handle = await AoLoader(wasm, options);
	const env = {
		Process: {
			Id: 'AOS',
			Owner: 'FOOBAR',
			Tags: [{ name: 'Name', value: 'Thomas' }],
		},
	};

	const data = `
		local es256k = require ".es256k"
		local bignum = require(".bint")(4096)
	
		local result = es256k.Fp.sqrt(bignum(64))
		return tostring(result)
	`;
	
	const msg = {
		Target: 'AOS',
		From: 'FOOBAR',
		Owner: 'FOOBAR',
		['Block-Height']: '1000',
		Id: '1234xyxfoo',
		Module: 'WOOPAWOOPA',
		Tags: [{ name: 'Action', value: 'Eval' }],
		Data: data,
	};

	const result = await handle(null, msg, env);

	console.log('Error:', result.Error, ", Result: ", result.Output?.data)
  assert.equal(result.Error, undefined)
  assert.equal(result.Output?.data, "8")
  assert.ok(true)
})

 test('Verify a signature', async () => {
  const handle = await AoLoader(wasm, options);
	const env = {
		Process: {
			Id: 'AOS',
			Owner: 'FOOBAR',
			Tags: [{ name: 'Name', value: 'Thomas' }],
		},
	};

	// This corresponds to validating the following JWT:
	// eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7InlvdSI6IlJvY2sifX0sInN1YiI6ImRpZDp3ZWI6ZXhhbXBsZS5jb20iLCJuYmYiOjE3MzQwMjgzMjIsImlzcyI6ImRpZDpldGhyOnNlcG9saWE6MHgwMmM2M2VmZTNkYzcwN2Y2ZTNkMzIzZjExZTQwY2YwNzU3OGIyYWI5YWVlMTYzNWU2ZWU2NzZmNmRhMDlmMTU5OGQifQ.VEHlsQ7rF5Z5lDuQPZjSp2Tsd-QM0tSB5SWBmE_jZpobbzDaKg1GPoAtZLBeoWwdNfjTxiyhyY08iYw3mCV4rg
	const data = `
		local es256k = require ".es256k"
		
		local sig = es256k.base64_url_decode('VEHlsQ7rF5Z5lDuQPZjSp2Tsd-QM0tSB5SWBmE_jZpobbzDaKg1GPoAtZLBeoWwdNfjTxiyhyY08iYw3mCV4rg')
		local msg = 'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7InlvdSI6IlJvY2sifX0sInN1YiI6ImRpZDp3ZWI6ZXhhbXBsZS5jb20iLCJuYmYiOjE3MzQwMjgzMjIsImlzcyI6ImRpZDpldGhyOnNlcG9saWE6MHgwMmM2M2VmZTNkYzcwN2Y2ZTNkMzIzZjExZTQwY2YwNzU3OGIyYWI5YWVlMTYzNWU2ZWU2NzZmNmRhMDlmMTU5OGQifQ'
		local success = es256k.verify_sig(msg, sig, '0x2a6ffb5341f8c1ce123343162e3351f1b6286c43')

		return success
	`;
	
	const msg = {
		Target: 'AOS',
		From: 'FOOBAR',
		Owner: 'FOOBAR',
		['Block-Height']: '1000',
		Id: '1234xyxfoo',
		Module: 'WOOPAWOOPA',
		Tags: [{ name: 'Action', value: 'Eval' }],
		Data: data,
	};

	const result = await handle(null, msg, env);

	// dropping .Memory cuz it's a huge byte array
  console.log('Error:', result.Error, ", Result: ", result.Output?.data)
  assert.equal(result.Error, undefined)
  assert.equal(result.Output?.data, "true")
  assert.ok(true)
})

 test('Validate a JWT', async () => {
  const handle = await AoLoader(wasm, options);
	const env = {
		Process: {
			Id: 'AOS',
			Owner: 'FOOBAR',
			Tags: [{ name: 'Name', value: 'Thomas' }],
		},
	};

	const data = `
		local es256k = require ".es256k"

		local jwt = 'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7InlvdSI6IlJvY2sifX0sInN1YiI6ImRpZDp3ZWI6ZXhhbXBsZS5jb20iLCJuYmYiOjE3MzQwMjg3ODAsImlzcyI6ImRpZDpldGhyOnNlcG9saWE6MHgwMmM2M2VmZTNkYzcwN2Y2ZTNkMzIzZjExZTQwY2YwNzU3OGIyYWI5YWVlMTYzNWU2ZWU2NzZmNmRhMDlmMTU5OGQifQ.VEHlsQ7rF5Z5lDuQPZjSp2Tsd-QM0tSB5SWBmE_jZppghPpee_pZyzigqsUCeWV9J0rt8SI2oS7uhjm1JaLrww'
		local result = es256k.jwt_validate(jwt)
		
		return result
	`;
	
	const msg = {
		Target: 'AOS',
		From: 'FOOBAR',
		Owner: 'FOOBAR',
		['Block-Height']: '1000',
		Id: '1234xyxfoo',
		Module: 'WOOPAWOOPA',
		Tags: [{ name: 'Action', value: 'Eval' }],
		Data: data,
	};

	const result = await handle(null, msg, env);

	console.log('Error:', result.Error, ", Result: ", result.Output?.data)
  assert.equal(result.Error, undefined)
  assert.equal(result.Output?.data, "true")
  assert.ok(true)
})

// Not sure if we need this test. Signing stuff via AO actors isn't really a useful thing to do due to lack of privacy.

//  test('Create and verify a signature', async () => {
//   const handle = await AoLoader(wasm, options);
// 	const env = {
// 		Process: {
// 			Id: 'AOS',
// 			Owner: 'FOOBAR',
// 			Tags: [{ name: 'Name', value: 'Thomas' }],
// 		},
// 	};

// 	const data = `
// 		local es256k = require ".es256k"
		
// 		local PRIV_KEY = "5a4a285d9e8726c011f20ff4133e0b417894929b3d053903c6831ea6bdc6930d"
// 		local msg = 'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7InlvdSI6IlJvY2sifX0sInN1YiI6ImRpZDp3ZWI6ZXhhbXBsZS5jb20iLCJuYmYiOjE3MzM1NDA2ODQsImlzcyI6ImRpZDpldGhyOnNlcG9saWE6MHgwMmM2M2VmZTNkYzcwN2Y2ZTNkMzIzZjExZTQwY2YwNzU3OGIyYWI5YWVlMTYzNWU2ZWU2NzZmNmRhMDlmMTU5OGQifQ'
// 		local sig = es256k.create_sig(msg, PRIV_KEY)
// 		local result_sig_verify1 = es256k.verify_sig(msg, sig, '0x2a6ffb5341f8c1ce123343162e3351f1b6286c43')

// 		return result_sig_verify1
// 	`;
	
// 	const msg = {
// 		Target: 'AOS',
// 		From: 'FOOBAR',
// 		Owner: 'FOOBAR',
// 		['Block-Height']: '1000',
// 		Id: '1234xyxfoo',
// 		Module: 'WOOPAWOOPA',
// 		Tags: [{ name: 'Action', value: 'Eval' }],
// 		Data: data,
// 	};

// 	const result = await handle(null, msg, env);

// 	// dropping .Memory cuz it's a huge byte array
//   console.log('Error:', result.Error, ", Result: ", result.Output?.data)
//   assert.equal(result.Error, undefined)
//   assert.equal(result.Output?.data, "true")
//   assert.ok(true)
// })