import { randomBytes } from 'crypto'
import { ValidationError } from '../../../error.js'
export const API_TOKEN_GENERATOR_SUPPORTED_BIT_LENGTHS = [64, 128, 256, 512, 1024, 2048] as const
export const API_TOKEN_GENERATOR_SUPPORTED_FORMATS = [
	'base64url',
	'base64',
	'hex',
	'alphanumeric',
] as const
export const API_TOKEN_GENERATOR_ENTROPY_THRESHOLDS = [
	{ min: 0, max: 64, label: 'WEAK' },
	{ min: 65, max: 128, label: 'FAIR' },
	{ min: 129, max: 192, label: 'GOOD' },
	{ min: 193, max: 256, label: 'STRONG' },
	{ min: 257, max: Infinity, label: 'VERY_STRONG' },
] as const
const API_TOKEN_GENERATOR_MIN_COUNT = 1
const API_TOKEN_GENERATOR_MAX_COUNT = 25
const API_TOKEN_GENERATOR_MAX_PREFIX_LENGTH = 20
const API_TOKEN_GENERATOR_PREFIX_REGEX = /^[a-zA-Z0-9_]+$/
const API_TOKEN_GENERATOR_BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
const API_TOKEN_GENERATOR_BASE32_LOOKUP = API_TOKEN_GENERATOR_BASE32_ALPHABET.split('')
export type ApiTokenGeneratorBitLength = (typeof API_TOKEN_GENERATOR_SUPPORTED_BIT_LENGTHS)[number]
export type ApiTokenGeneratorFormat = (typeof API_TOKEN_GENERATOR_SUPPORTED_FORMATS)[number]
export interface ApiTokenGeneratorGenerateOptions {
	count?: number
	bitLength?: ApiTokenGeneratorBitLength
	format?: ApiTokenGeneratorFormat
	prefix?: string
}
export interface ApiTokenGeneratorItem {
	token: string
}
export interface ApiTokenGeneratorGenerateResult {
	tokens: readonly ApiTokenGeneratorItem[]
	metadata: {
		count: number
		bitLength: ApiTokenGeneratorBitLength
		format: ApiTokenGeneratorFormat
		prefix?: string
		entropyStrength?: string
	}
}
interface ApiTokenGeneratorValidationRule {
	validate: (value: any) => void
}
function apiTokenGeneratorBase32Encode(buffer: Buffer): string {
	let bits = 0
	let value = 0
	let output = ''
	for (let i = 0; i < buffer.length; i++) {
		const byte = buffer[i]!
		value = (value << 8) | byte
		bits += 8
		while (bits >= 5) {
			const index = (value >>> (bits - 5)) & 31
			output += API_TOKEN_GENERATOR_BASE32_LOOKUP[index]
			bits -= 5
		}
	}
	if (bits > 0) {
		const index = (value << (5 - bits)) & 31
		output += API_TOKEN_GENERATOR_BASE32_LOOKUP[index]
	}
	return output
}
function apiTokenGeneratorGetEntropyStrength(bitLength: number): string {
	const threshold = API_TOKEN_GENERATOR_ENTROPY_THRESHOLDS.find(
		(t) => bitLength >= t.min && bitLength <= t.max,
	)
	return threshold?.label ?? 'UNKNOWN'
}
const apiTokenGeneratorGenerators: Record<ApiTokenGeneratorFormat, (bytes: Buffer) => string> = {
	base64url: (buf) => buf.toString('base64url'),
	base64: (buf) => buf.toString('base64').replace(/=+$/, ''),
	hex: (buf) => buf.toString('hex'),
	alphanumeric: apiTokenGeneratorBase32Encode,
}
function apiTokenGeneratorCreateValidator<T extends ApiTokenGeneratorGenerateOptions>(rules: {
	[K in keyof T]?: ApiTokenGeneratorValidationRule
}) {
	return (
		options: T,
	): Required<Pick<T, keyof T>> & { prefix?: string; format: ApiTokenGeneratorFormat } => {
		const result: any = {}
		for (const key in rules) {
			const rule = rules[key]
			const value =
				options[key] ??
				(() => {
					switch (key) {
						case 'count':
							return API_TOKEN_GENERATOR_MIN_COUNT
						case 'bitLength':
							return 256
						case 'format':
							return 'base64url'
						default:
							return undefined
					}
				})()
			if (rule?.validate) {
				rule.validate(value)
			}
			result[key] = value
		}
		return result
	}
}
const apiTokenGeneratorValidateOptions =
	apiTokenGeneratorCreateValidator<ApiTokenGeneratorGenerateOptions>({
		count: {
			validate: (val) => {
				if (
					!Number.isInteger(val) ||
					val < API_TOKEN_GENERATOR_MIN_COUNT ||
					val > API_TOKEN_GENERATOR_MAX_COUNT
				) {
					throw new ValidationError(
						`count must be an integer between ${API_TOKEN_GENERATOR_MIN_COUNT} and ${API_TOKEN_GENERATOR_MAX_COUNT}`,
						{ count: val },
					)
				}
			},
		},
		bitLength: {
			validate: (val) => {
				if (!API_TOKEN_GENERATOR_SUPPORTED_BIT_LENGTHS.includes(val)) {
					throw new ValidationError(
						`bitLength must be one of: ${API_TOKEN_GENERATOR_SUPPORTED_BIT_LENGTHS.join(', ')}`,
						{ bitLength: val },
					)
				}
			},
		},
		format: {
			validate: (val) => {
				if (!API_TOKEN_GENERATOR_SUPPORTED_FORMATS.includes(val)) {
					throw new ValidationError(
						`format must be one of: ${API_TOKEN_GENERATOR_SUPPORTED_FORMATS.join(', ')}`,
						{ format: val },
					)
				}
			},
		},
		prefix: {
			validate: (val) => {
				if (val !== undefined) {
					if (typeof val !== 'string') {
						throw new ValidationError('prefix must be a string', { prefix: val })
					}
					if (val.length > API_TOKEN_GENERATOR_MAX_PREFIX_LENGTH) {
						throw new ValidationError(
							`prefix length must not exceed ${API_TOKEN_GENERATOR_MAX_PREFIX_LENGTH} characters`,
							{ prefixLength: val.length },
						)
					}
					if (!API_TOKEN_GENERATOR_PREFIX_REGEX.test(val)) {
						throw new ValidationError(
							'prefix may only contain alphanumeric characters and underscores',
							{ prefix: val },
						)
					}
				}
			},
		},
	})
function* apiTokenGeneratorGenerateTokenItems(
	count: number,
	bitLength: ApiTokenGeneratorBitLength,
	format: ApiTokenGeneratorFormat,
	prefix: string | undefined,
): Generator<ApiTokenGeneratorItem, void, unknown> {
	const byteLength = bitLength / 8
	for (let i = 0; i < count; i++) {
		const bytes = randomBytes(byteLength)
		const tokenRaw = apiTokenGeneratorGenerators[format](bytes)
		const token = prefix ? `${prefix}_${tokenRaw}` : tokenRaw
		yield { token }
	}
}
function apiTokenGeneratorCollectGenerator<T>(gen: Generator<T>): T[] {
	const result: T[] = []
	for (const item of gen) {
		result.push(item)
	}
	return result
}
export function apiTokenGeneratorGenerateTokens(
	options: ApiTokenGeneratorGenerateOptions = {},
): ApiTokenGeneratorGenerateResult {
	const { count, bitLength, format, prefix } = apiTokenGeneratorValidateOptions(options)
	const gen = apiTokenGeneratorGenerateTokenItems(count, bitLength, format, prefix)
	const tokens = apiTokenGeneratorCollectGenerator(gen)
	const entropyStrength = apiTokenGeneratorGetEntropyStrength(bitLength)
	const metadata: ApiTokenGeneratorGenerateResult['metadata'] = {
		count,
		bitLength,
		format,
		entropyStrength,
		...(prefix && { prefix }),
	}
	return { tokens, metadata }
}
export function apiTokenGeneratorExportTokens(
	result: ApiTokenGeneratorGenerateResult,
	exportFormat: 'json' | 'txt' | 'csv' = 'json',
): string {
	const { tokens, metadata } = result
	switch (exportFormat) {
		case 'json':
			return JSON.stringify({ metadata, tokens }, null, 2)
		case 'txt':
			return tokens.map((t) => t.token).join('\n\n')
		case 'csv': {
			const headers = ['token']
			const escapeCsv = (str: string) => {
				if (str.includes('"') || str.includes(',') || str.includes('\n')) {
					return `"${str.replace(/"/g, '""')}"`
				}
				return str
			}
			const rows = tokens.map((t) => escapeCsv(t.token))
			return headers.join(',') + '\n' + rows.join('\n')
		}
		default:
			throw new ValidationError(`Unsupported export format: ${exportFormat}`)
	}
}
export function apiTokenGeneratorGenerateSample(): ApiTokenGeneratorItem {
	const result = apiTokenGeneratorGenerateTokens({
		count: 1,
		bitLength: 256,
		format: 'base64url',
	})
	return result.tokens[0]!
}
// ============================================================================
// Kelas dengan method yang juga diperpanjang
// ============================================================================
export class ApiTokenGeneratorGenerator {
	private options: ReturnType<typeof apiTokenGeneratorValidateOptions>
	constructor(options: ApiTokenGeneratorGenerateOptions = {}) {
		this.options = apiTokenGeneratorValidateOptions(options)
	}
	public apiTokenGeneratorGenerateInstance(): ApiTokenGeneratorGenerateResult {
		const { count, bitLength, format, prefix } = this.options
		const gen = apiTokenGeneratorGenerateTokenItems(count, bitLength, format, prefix)
		const tokens = apiTokenGeneratorCollectGenerator(gen)
		const entropyStrength = apiTokenGeneratorGetEntropyStrength(bitLength)
		const metadata: ApiTokenGeneratorGenerateResult['metadata'] = {
			count,
			bitLength,
			format,
			entropyStrength,
			...(prefix && { prefix }),
		}
		return { tokens, metadata }
	}
	public apiTokenGeneratorExportInstance(
		result: ApiTokenGeneratorGenerateResult,
		exportFormat: 'json' | 'txt' | 'csv' = 'json',
	): string {
		return apiTokenGeneratorExportTokens(result, exportFormat)
	}
}
