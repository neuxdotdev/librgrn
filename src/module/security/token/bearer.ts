import { randomBytes } from 'crypto'
import { ValidationError } from '../../../error.js'
export type BearerFormat = 'base64url' | 'base64' | 'hex' | 'alphanumeric'
export interface BearerGenerateOptions {
	count?: number
	length?: 16 | 32 | 64 | 128

	format?: BearerFormat
}
export interface BearerGeneratedToken {
	token: string
	byteLength: number
	format: BearerFormat
}
export interface BearerGenerateResult {
	tokens: BearerGeneratedToken[]
	metadata: {
		count: number
		length: number
		format: BearerFormat
	}
}
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
function base32Encode(buffer: Buffer): string {
	let bits = 0
	let value = 0
	let output = ''
	for (let i = 0; i < buffer.length; i++) {
		const byte = buffer[i]
		if (byte === undefined) throw new Error('Unexpected undefined byte in buffer')
		value = (value << 8) | byte
		bits += 8
		while (bits >= 5) {
			output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31]
			bits -= 5
		}
	}
	if (bits > 0) {
		output += BASE32_ALPHABET[(value << (5 - bits)) & 31]
	}
	return output
}
export function generateBearerTokens(options: BearerGenerateOptions = {}): BearerGenerateResult {
	const { count = 1, length = 32, format = 'base64url' } = options
	if (count < 1 || count > 50) {
		throw new ValidationError('count must be between 1 and 50', { count })
	}
	const validLengths = [16, 32, 64, 128] as const
	if (!validLengths.includes(length as any)) {
		throw new ValidationError('length must be 16, 32, 64, or 128', { length })
	}
	const tokens: BearerGeneratedToken[] = []
	for (let i = 0; i < count; i++) {
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
		tokens.push({ token, byteLength: length, format })
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
