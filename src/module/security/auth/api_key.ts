import { randomBytes, randomUUID } from 'crypto'
import { ValidationError } from '../../../error.js'
export const API_KEY_SUPPORTED_FORMATS = [
	'alphanumeric',
	'hex',
	'base64',
	'base64url',
	'uuid',
	'numeric',
] as const
export const API_KEY_ENTROPY_THRESHOLDS = [
	{ min: 0, max: 64, label: 'WEAK' },
	{ min: 65, max: 128, label: 'FAIR' },
	{ min: 129, max: 192, label: 'GOOD' },
	{ min: 193, max: 256, label: 'STRONG' },
	{ min: 257, max: Infinity, label: 'VERY_STRONG' },
] as const
const API_KEY_MIN_COUNT = 1
const API_KEY_MAX_COUNT = 25
const API_KEY_MIN_LENGTH = 8
const API_KEY_MAX_LENGTH = 256
const API_KEY_MAX_PREFIX_LENGTH = 20
const API_KEY_PREFIX_REGEX = /^[a-zA-Z0-9_]+$/
const API_KEY_BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
const API_KEY_BASE32_LOOKUP = API_KEY_BASE32_ALPHABET.split('')
export type ApiKeyFormat = (typeof API_KEY_SUPPORTED_FORMATS)[number]
export interface ApiKeyGenerateOptions {
	count?: number
	length?: number
	format?: ApiKeyFormat
	prefix?: string
	includeSecret?: boolean
	secretLength?: number
	secretFormat?: ApiKeyFormat
}
export interface ApiKeyItem {
	key: string
	secret?: string
}
export interface ApiKeyGenerateResult {
	keys: readonly ApiKeyItem[]
	metadata: {
		count: number
		length: number
		format: ApiKeyFormat
		prefix?: string
		includeSecret: boolean
		secretLength?: number
		secretFormat?: ApiKeyFormat
		entropyStrength?: string
	}
}
interface ApiKeyValidationRule {
	validate: (value: any) => void
	required?: boolean
}
function apiKeyBase32Encode(buffer: Buffer): string {
	let bits = 0
	let value = 0
	let output = ''
	for (let i = 0; i < buffer.length; i++) {
		const byte = buffer[i]!
		value = (value << 8) | byte
		bits += 8
		while (bits >= 5) {
			const index = (value >>> (bits - 5)) & 31
			output += API_KEY_BASE32_LOOKUP[index]
			bits -= 5
		}
	}
	if (bits > 0) {
		const index = (value << (5 - bits)) & 31
		output += API_KEY_BASE32_LOOKUP[index]
	}
	return output
}
function apiKeyGenerateNumericString(length: number): string {
	const bytes = randomBytes(Math.ceil(length * 0.5))
	let result = ''
	let byteIndex = 0
	while (result.length < length) {
		if (byteIndex >= bytes.length) {
			bytes.set(randomBytes(Math.ceil((length - result.length) * 0.5)), 0)
			byteIndex = 0
		}
		const byte = bytes[byteIndex]!
		if (byte <= 99) {
			const twoDigits = byte < 10 ? `0${byte}` : `${byte}`
			result += twoDigits
		}
		byteIndex++
	}
	return result.slice(0, length)
}
function apiKeyGetEntropyStrength(byteLength: number): string {
	const bits = byteLength * 8
	const threshold = API_KEY_ENTROPY_THRESHOLDS.find((t) => bits >= t.min && bits <= t.max)
	return threshold?.label ?? 'UNKNOWN'
}
const apiKeyGenerators: Record<ApiKeyFormat, (length: number) => string> = {
	alphanumeric: (len) => apiKeyBase32Encode(randomBytes(len)),
	hex: (len) => randomBytes(len).toString('hex'),
	base64: (len) => randomBytes(len).toString('base64').replace(/=+$/, ''),
	base64url: (len) => randomBytes(len).toString('base64url'),
	uuid: () => randomUUID(),
	numeric: (len) => apiKeyGenerateNumericString(len),
}
function apiKeyCreateValidator<T extends ApiKeyGenerateOptions>(rules: {
	[K in keyof T]?: ApiKeyValidationRule
}) {
	return (
		options: T,
	): Required<Pick<T, keyof T>> & {
		prefix?: string
		secretLength: number
		secretFormat: ApiKeyFormat
	} => {
		const result: any = {}
		for (const key in rules) {
			const rule = rules[key]
			const value =
				options[key] ??
				(rule?.required
					? undefined
					: (() => {
							switch (key) {
								case 'count':
									return API_KEY_MIN_COUNT
								case 'length':
									return 32
								case 'format':
									return 'alphanumeric'
								case 'includeSecret':
									return false
								default:
									return undefined
							}
						})())
			if (rule?.validate) {
				rule.validate(value)
			}
			result[key] = value
		}
		result.secretLength = options.secretLength ?? result.length
		result.secretFormat = options.secretFormat ?? result.format
		if (options.includeSecret) {
			if (options.secretLength !== undefined) {
				if (
					!Number.isInteger(options.secretLength) ||
					options.secretLength < API_KEY_MIN_LENGTH ||
					options.secretLength > API_KEY_MAX_LENGTH
				) {
					throw new ValidationError(
						`secretLength must be an integer between ${API_KEY_MIN_LENGTH} and ${API_KEY_MAX_LENGTH}`,
						{ secretLength: options.secretLength },
					)
				}
			}
			if (
				options.secretFormat !== undefined &&
				!API_KEY_SUPPORTED_FORMATS.includes(options.secretFormat)
			) {
				throw new ValidationError(
					`secretFormat must be one of: ${API_KEY_SUPPORTED_FORMATS.join(', ')}`,
					{ secretFormat: options.secretFormat },
				)
			}
		}
		return result
	}
}
const apiKeyValidateOptions = apiKeyCreateValidator<ApiKeyGenerateOptions>({
	count: {
		validate: (val) => {
			if (!Number.isInteger(val) || val < API_KEY_MIN_COUNT || val > API_KEY_MAX_COUNT) {
				throw new ValidationError(
					`count must be an integer between ${API_KEY_MIN_COUNT} and ${API_KEY_MAX_COUNT}`,
					{ count: val },
				)
			}
		},
	},
	length: {
		validate: (val) => {
			if (!Number.isInteger(val) || val < API_KEY_MIN_LENGTH || val > API_KEY_MAX_LENGTH) {
				throw new ValidationError(
					`length must be an integer between ${API_KEY_MIN_LENGTH} and ${API_KEY_MAX_LENGTH}`,
					{ length: val },
				)
			}
		},
	},
	format: {
		validate: (val) => {
			if (!API_KEY_SUPPORTED_FORMATS.includes(val)) {
				throw new ValidationError(
					`format must be one of: ${API_KEY_SUPPORTED_FORMATS.join(', ')}`,
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
				if (val.length > API_KEY_MAX_PREFIX_LENGTH) {
					throw new ValidationError(
						`prefix length must not exceed ${API_KEY_MAX_PREFIX_LENGTH} characters`,
						{ prefixLength: val.length },
					)
				}
				if (!API_KEY_PREFIX_REGEX.test(val)) {
					throw new ValidationError(
						'prefix may only contain alphanumeric characters and underscores',
						{ prefix: val },
					)
				}
			}
		},
	},
	includeSecret: {
		validate: (val) => {
			if (typeof val !== 'boolean') {
				throw new ValidationError('includeSecret must be a boolean', {
					includeSecret: val,
				})
			}
		},
	},
})
function* apiKeyGenerateKeyItems(
	count: number,
	length: number,
	format: ApiKeyFormat,
	prefix: string | undefined,
	includeSecret: boolean,
	secretLength: number,
	secretFormat: ApiKeyFormat,
): Generator<ApiKeyItem, void, unknown> {
	for (let i = 0; i < count; i++) {
		const generator = apiKeyGenerators[format]
		const keyRaw = generator(length)
		const key = prefix ? `${prefix}_${keyRaw}` : keyRaw
		const item: ApiKeyItem = { key }
		if (includeSecret) {
			const secretGenerator = apiKeyGenerators[secretFormat]
			const secretRaw = secretGenerator(secretLength)
			item.secret = prefix ? `${prefix}_${secretRaw}` : secretRaw
		}
		yield item
	}
}
function apiKeyCollectGenerator<T>(gen: Generator<T>): T[] {
	const result: T[] = []
	for (const item of gen) {
		result.push(item)
	}
	return result
}
export function apiKeyGenerateTokens(options: ApiKeyGenerateOptions = {}): ApiKeyGenerateResult {
	const { count, length, format, prefix, includeSecret, secretLength, secretFormat } =
		apiKeyValidateOptions(options)
	const gen = apiKeyGenerateKeyItems(
		count,
		length,
		format,
		prefix,
		includeSecret,
		secretLength,
		secretFormat,
	)
	const keys = apiKeyCollectGenerator(gen)
	const entropyStrength = keys.length > 0 ? apiKeyGetEntropyStrength(length) : undefined
	const metadata: ApiKeyGenerateResult['metadata'] = {
		count,
		length,
		format,
		includeSecret,
		...(prefix && { prefix }),
		...(includeSecret && { secretLength, secretFormat }),
		...(entropyStrength && { entropyStrength }),
	}
	return { keys, metadata }
}
export function apiKeyExportTokens(
	result: ApiKeyGenerateResult,
	exportFormat: 'json' | 'txt' | 'csv' = 'json',
): string {
	const { keys, metadata } = result
	switch (exportFormat) {
		case 'json':
			return JSON.stringify({ metadata, keys }, null, 2)
		case 'txt': {
			return keys
				.map((item) => {
					const lines = [`key: ${item.key}`]
					if (item.secret) lines.push(`secret: ${item.secret}`)
					return lines.join('\n')
				})
				.join('\n\n')
		}
		case 'csv': {
			const hasSecret = keys.some((item) => item.secret)
			const headers = ['key']
			if (hasSecret) headers.push('secret')
			const escapeCsv = (str: string) => {
				if (str.includes('"') || str.includes(',') || str.includes('\n')) {
					return `"${str.replace(/"/g, '""')}"`
				}
				return str
			}
			const rows = keys.map((item) => {
				const cols = [escapeCsv(item.key)]
				if (hasSecret) cols.push(item.secret ? escapeCsv(item.secret) : '')
				return cols.join(',')
			})
			return headers.join(',') + '\n' + rows.join('\n')
		}
		default:
			throw new ValidationError(`Unsupported export format: ${exportFormat}`)
	}
}
export function apiKeyGenerateSample(): ApiKeyItem {
	const result = apiKeyGenerateTokens({
		count: 1,
		length: 32,
		format: 'alphanumeric',
		includeSecret: false,
	})
	return result.keys[0]!
}
export class ApiKeyGenerator {
	private options: ReturnType<typeof apiKeyValidateOptions>
	constructor(options: ApiKeyGenerateOptions = {}) {
		this.options = apiKeyValidateOptions(options)
	}
	public apiKeyGenerateInstance(): ApiKeyGenerateResult {
		const { count, length, format, prefix, includeSecret, secretLength, secretFormat } =
			this.options
		const gen = apiKeyGenerateKeyItems(
			count,
			length,
			format,
			prefix,
			includeSecret,
			secretLength,
			secretFormat,
		)
		const keys = apiKeyCollectGenerator(gen)
		const entropyStrength = keys.length > 0 ? apiKeyGetEntropyStrength(length) : undefined
		const metadata: ApiKeyGenerateResult['metadata'] = {
			count,
			length,
			format,
			includeSecret,
			...(prefix && { prefix }),
			...(includeSecret && { secretLength, secretFormat }),
			...(entropyStrength && { entropyStrength }),
		}
		return { keys, metadata }
	}
	public apiKeyExportInstance(
		result: ApiKeyGenerateResult,
		exportFormat: 'json' | 'txt' | 'csv' = 'json',
	): string {
		return apiKeyExportTokens(result, exportFormat)
	}
}
