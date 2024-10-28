import { test } from 'node:test'
import * as assert from 'node:assert'
import AoLoader from '@permaweb/ao-loader'
import fs from 'fs'

const wasm = fs.readFileSync('./process.wasm')
const options = { format: "wasm64-unknown-emscripten-draft_2024_02_15" }

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

// test('print hello world', async () => {
//   const handle = await AoLoader(wasm, options)
//   const env = {
//     Process: {
//       Id: 'AOS',
//       Owner: 'FOOBAR',
//       Tags: [
//         { name: 'Name', value: 'Thomas' }
//       ]
//     }
//   }
//   const msg = {
//     Target: 'AOS',
//     From: 'FOOBAR',
//     Owner: 'FOOBAR',
//     ['Block-Height']: "1000",
//     Id: "1234xyxfoo",
//     Module: "WOOPAWOOPA",
//     Tags: [
//       { name: 'Action', value: 'Eval' }
//     ],
//     Data: `print("Hello World")`

//   }
//   const result = await handle(null, msg, env)
//   assert.equal(result.Output?.data, "Hello World")
//   assert.ok(true)
// })


// test('create an Assignment', async () => {
//   const handle = await AoLoader(wasm, options)
//   const env = {
//     Process: {
//       Id: 'AOS',

//       Owner: 'FOOBAR',
//       Tags: [
//         { name: 'Name', value: 'Thomas' }
//       ]
//     }
//   }
//   const msg = {
//     Target: 'AOS',
//     From: 'FOOBAR',
//     Owner: 'FOOBAR',
//     ['Block-Height']: "1000",
//     Id: "1234xyxfoo",
//     Module: "WOOPAWOOPA",
//     Tags: [
//       { name: 'Action', value: 'Eval' }
//     ],
//     Data: 'Assign({ Processes = { "pid-1", "pid-2" }, Message = "mid-1" })'
//   }
//   const result = await handle(null, msg, env)

//   assert.deepStrictEqual(result.Assignments, [
//     { Processes: ['pid-1', 'pid-2'], Message: 'mid-1' }
//   ])
//   assert.ok(true)
// })