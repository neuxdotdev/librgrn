import { randomBytes } from 'crypto'
import { ValidationError } from '../../../error.js'
export type BearerFormat = 'base64url' | 'base64' | 'hex' | 'alphanumeric'
export type BearerLength = 16 | 32 | 64 | 128
export interface BearerGenerateOptions {
	count?: number
	length?: BearerLength
	format?: BearerFormat
}
export interface BearerGeneratedToken {
	token: string
	byteLength: BearerLength
	format: BearerFormat
}
export interface BearerGenerateResult {
	tokens: BearerGeneratedToken[]
	metadata: {
		count: number
		length: BearerLength
		format: BearerFormat
	}
}
const VALID_LENGTHS: BearerLength[] = [16, 32, 64, 128]
const MAX_COUNT = 50
const MIN_COUNT = 1
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
function base32Encode(buffer: Buffer): string {
	let bits = 0
	let value = 0
	let output = ''
	for (let i = 0; i < buffer.length; i++) {
		const byte = buffer[i]!
		value = (value << 8) | byte
		bits += 8
		while (bits >= 5) {
			const index = (value >>> (bits - 5)) & 31
			output += BASE32_ALPHABET[index]
			bits -= 5
		}
	}
	if (bits > 0) {
		const index = (value << (5 - bits)) & 31
		output += BASE32_ALPHABET[index]
	}
	return output
}
function validateGenerateOptions(options: BearerGenerateOptions): Required<BearerGenerateOptions> {
	const count = options.count ?? 1
	if (count < MIN_COUNT || count > MAX_COUNT) {
		throw new ValidationError(`count must be between ${MIN_COUNT} and ${MAX_COUNT}`, { count })
	}
	const length = options.length ?? 32
	if (!VALID_LENGTHS.includes(length)) {
		throw new ValidationError(`length must be one of: ${VALID_LENGTHS.join(', ')}`, { length })
	}
	const format = options.format ?? 'base64url'
	return { count, length, format }
}
function generateSingleToken(length: BearerLength, format: BearerFormat): BearerGeneratedToken {
	const bytes = randomBytes(length)
	let token: string
	switch (format) {
		case 'base64url':
			token = bytes.toString('base64url')
			break
		case 'base64':
			token = bytes.toString('base64').replace(/=+$/, '')
			break
		case 'hex':
			token = bytes.toString('hex')
			break
		case 'alphanumeric':
			token = base32Encode(bytes)
			break
		default:
			throw new ValidationError(`Unsupported format: ${format}`)
	}
	return { token, byteLength: length, format }
}
export function generateBearerTokens(options: BearerGenerateOptions = {}): BearerGenerateResult {
	const { count, length, format } = validateGenerateOptions(options)
	const tokens: BearerGeneratedToken[] = []
	for (let i = 0; i < count; i++) {
		tokens.push(generateSingleToken(length, format))
	}
	return {
		tokens,
		metadata: { count, length, format },
	}
}
export function exportBearerTokens(
	result: BearerGenerateResult,
	format: 'json' | 'csv' | 'txt' = 'json',
): string {
	const { tokens, metadata } = result
	switch (format) {
		case 'json':
			return JSON.stringify({ metadata, tokens }, null, 2)
		case 'txt':
			return tokens.map((t) => t.token).join('\n')
		case 'csv': {
			const header = 'token,byteLength,format\n'
			const rows = tokens.map((t) => `"${t.token}",${t.byteLength},${t.format}`).join('\n')
			return header + rows
		}
		default:
			throw new ValidationError('Unsupported export format', { format })
	}
}
export function generateBearerTokenSample(): BearerGeneratedToken {
	const result = generateBearerTokens({
		count: 1,
		length: 32,
		format: 'base64url',
	})
	const token = result.tokens[0]
	if (!token) {
		throw new Error('Failed to generate bearer token sample')
	}
	return token
}
