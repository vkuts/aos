import { test } from 'node:test'
import * as assert from 'node:assert'
import AoLoader from '@permaweb/ao-loader'
import fs from 'fs'

const wasm = fs.readFileSync('./process.wasm')
const options = {
	format: "wasm32-unknown-emscripten4", // wasm64-unknown-emscripten-draft_2024_02_15
 }

 test('Use vlad_rusty to get ohai', async () => {
  const handle = await AoLoader(wasm, options);
	const env = {
		Process: {
			Id: 'AOS',
			Owner: 'FOOBAR',
			Tags: [{ name: 'Name', value: 'Thomas' }],
		},
	};

	const data = `
    local result = get_ohai()
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

  assert.equal(result.Error, undefined)
  assert.equal(result.Output?.data, "ohai")
  assert.ok(true)
})

test('Use vlad_rusty to say hi to a fren', async () => {
  const handle = await AoLoader(wasm, options);
	const env = {
		Process: {
			Id: 'AOS',
			Owner: 'FOOBAR',
			Tags: [{ name: 'Name', value: 'Thomas' }],
		},
	};

	const data = `
    local result = say_hi("Vic")
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

  assert.equal(result.Error, undefined)
  assert.equal(result.Output?.data, "ohai")
  assert.ok(true)
})

//  test('Use didkit.add_two_integers successfully', async () => {
//   const handle = await AoLoader(wasm, options);
// 	const env = {
// 		Process: {
// 			Id: 'AOS',
// 			Owner: 'FOOBAR',
// 			Tags: [{ name: 'Name', value: 'Thomas' }],
// 		},
// 	};

// 	const data = `
//     local result = add_two_integers(3, 4)
// 		return result
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

//   assert.equal(result.Error, undefined)
//   assert.equal(result.Output?.data, "7")
//   assert.ok(true)
// })

test('Use vlad_rusty.add_two_integers successfully', async () => {
  const handle = await AoLoader(wasm, options);
	const env = {
		Process: {
			Id: 'AOS',
			Owner: 'FOOBAR',
			Tags: [{ name: 'Name', value: 'Thomas' }],
		},
	};

	const data = `
    local result = add_two_integers(3, 4)
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

  assert.equal(result.Error, undefined)
  assert.equal(result.Output?.data, "7")
  assert.ok(true)
})

test('Use vlad_rusty.subtract_two_integers successfully', async () => {
  const handle = await AoLoader(wasm, options);
	const env = {
		Process: {
			Id: 'AOS',
			Owner: 'FOOBAR',
			Tags: [{ name: 'Name', value: 'Thomas' }],
		},
	};

	const data = `
    local result = subtract_two_integers(3, 4)
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

  assert.equal(result.Error, undefined)
  assert.equal(result.Output?.data, "-1")
  assert.ok(true)
})

test('Use foo lib successfully', async () => {
  const handle = await AoLoader(wasm, options);
	const env = {
		Process: {
			Id: 'AOS',
			Owner: 'FOOBAR',
			Tags: [{ name: 'Name', value: 'Thomas' }],
		},
	};

	const data = `
		local foo = require ".foo"

		local n = 100
    local result = foo.bar()
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

  assert.equal(result.Error, undefined)
  assert.equal(result.Output?.data, "baz")
  assert.ok(true)
})

test('Use luafun lib successfully', async () => {
  const handle = await AoLoader(wasm, options);
	const env = {
		Process: {
			Id: 'AOS',
			Owner: 'FOOBAR',
			Tags: [{ name: 'Name', value: 'Thomas' }],
		},
	};

	const data = `
		local fun = require ".fun"

		local n = 100
    local result = fun.range(n):map(function(x) return x^2 end):reduce(fun.operator.add, 0)
    -- print("Result is " .. result)
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

  // assert.equal(result.Error, undefined)
  assert.equal(result.Output?.data, "338350.0")
  assert.ok(true)
})

test('run evaluate action successfully', async () => {
  const handle = await AoLoader(wasm, options)
  const env = {
    Process: {
      Id: 'AOS',
      Owner: 'FOOBAR',
      Tags: [
        { name: 'Name', value: 'Thomas' }
      ]
    }
  }
  const msg = {
    Target: 'AOS',
    From: 'FOOBAR',
    Owner: 'FOOBAR',
    ['Block-Height']: "1000",
    Id: "1234xyxfoo",
    Module: "WOOPAWOOPA",
    Tags: [
      { name: 'Action', value: 'Eval' }
    ],
    Data: '1 + 1'
  }
  const result = await handle(null, msg, env)
  assert.equal(result.Output?.data, '2')
  assert.ok(true)
})