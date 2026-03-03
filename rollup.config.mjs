import resolve from '@rollup/plugin-node-resolve'
import commonjs from '@rollup/plugin-commonjs'
import dts from 'rollup-plugin-dts'

export default [
	{
		input: 'dist/lib.js',
		plugins: [
			resolve({
				preferBuiltins: true,
			}),
			commonjs(),
		],
		output: [
			{
				file: 'build/lib.cjs',
				format: 'cjs',
				sourcemap: true,
			},
			{
				file: 'build/lib.js',
				format: 'esm',
				sourcemap: true,
			},
		],
	},

	// Type bundling
	{
		input: 'dist/lib.d.ts',
		output: [{ file: 'build/lib.d.ts', format: 'es' }],
		plugins: [dts()],
	},
]
