import { randomBytes } from 'crypto'
import { ValidationError } from '../../../error.js'
export const BARER_GENERATOR_MIN_LENGTH = 16
export const BARER_GENERATOR_MAX_LENGTH = 128
export const BARER_GENERATOR_DEFAULT_LENGTH = 32
export const BARER_GENERATOR_MIN_COUNT = 1
export const BARER_GENERATOR_MAX_COUNT = 50
export const BARER_GENERATOR_DEFAULT_COUNT = 1
export const BARER_GENERATOR_SUPPORTED_LENGTHS = Object.freeze([16, 32, 64, 128] as const)
export const BARER_GENERATOR_SUPPORTED_FORMATS = Object.freeze([
	'base64url',
	'base64',
	'hex',
	'alphanumeric',
] as const)
export const BARER_GENERATOR_SUPPORTED_EXPORT_FORMATS = Object.freeze([
	'json',
	'txt',
	'csv',
] as const)
export const BARER_GENERATOR_BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
export const BARER_GENERATOR_ENTROPY_THRESHOLDS = Object.freeze([
	{ min: 0, max: 63, label: 'weak' as const },
	{ min: 64, max: 127, label: 'medium' as const },
	{ min: 128, max: 255, label: 'strong' as const },
	{ min: 256, max: Infinity, label: 'very_strong' as const },
] as const)
export type BarerGeneratorFormat = (typeof BARER_GENERATOR_SUPPORTED_FORMATS)[number]
export type BarerGeneratorLength = (typeof BARER_GENERATOR_SUPPORTED_LENGTHS)[number]
export type BarerGeneratorExportFormat = (typeof BARER_GENERATOR_SUPPORTED_EXPORT_FORMATS)[number]
export type BarerGeneratorStrength = 'weak' | 'medium' | 'strong' | 'very_strong'
export interface BarerGeneratorGenerateOptions {
	count?: number
	length?: BarerGeneratorLength
	format?: BarerGeneratorFormat
	prefix?: string
	includeTimestamp?: boolean
	includeEntropy?: boolean
}
export interface BarerGeneratorGeneratedToken {
	readonly token: string
	readonly byteLength: BarerGeneratorLength
	readonly format: BarerGeneratorFormat
	readonly prefix?: string
	readonly timestamp?: number
	readonly entropyBits?: number
}
export interface BarerGeneratorGenerateMetadata {
	readonly count: number
	readonly length: BarerGeneratorLength
	readonly format: BarerGeneratorFormat
	readonly prefix?: string
	readonly includeTimestamp: boolean
	readonly includeEntropy: boolean
	readonly poolSize: number
	readonly avgEntropyBits: number
	readonly strength: BarerGeneratorStrength
}
export interface BarerGeneratorGenerateResult {
	readonly tokens: readonly BarerGeneratorGeneratedToken[]
	readonly metadata: BarerGeneratorGenerateMetadata
}
export interface BarerGeneratorValidationResult {
	readonly isValid: boolean
	readonly strength: BarerGeneratorStrength
	readonly entropyBits: number
	readonly length: number
	readonly format: BarerGeneratorFormat | 'unknown'
	readonly errors: readonly string[]
	readonly warnings: readonly string[]
}
function barerGeneratorBase32Encode(buffer: Buffer): string {
	let bits = 0
	let value = 0
	let output = ''
	for (let i = 0; i < buffer.length; i++) {
		const byte = buffer[i]!
		value = (value << 8) | byte
		bits += 8
		while (bits >= 5) {
			const index = (value >>> (bits - 5)) & 31
			output += BARER_GENERATOR_BASE32_ALPHABET[index]!
			bits -= 5
		}
	}
	if (bits > 0) {
		const index = (value << (5 - bits)) & 31
		output += BARER_GENERATOR_BASE32_ALPHABET[index]!
	}
	return output
}
function barerGeneratorValidateOptions(
	options: BarerGeneratorGenerateOptions = {},
): Required<Omit<BarerGeneratorGenerateOptions, 'prefix'>> & { prefix?: string } {
	const count = options.count ?? BARER_GENERATOR_DEFAULT_COUNT
	if (
		!Number.isInteger(count) ||
		count < BARER_GENERATOR_MIN_COUNT ||
		count > BARER_GENERATOR_MAX_COUNT
	) {
		throw new ValidationError(
			`count must be an integer between ${BARER_GENERATOR_MIN_COUNT} and ${BARER_GENERATOR_MAX_COUNT}`,
			{ count },
		)
	}
	const length = options.length ?? BARER_GENERATOR_DEFAULT_LENGTH
	if (!BARER_GENERATOR_SUPPORTED_LENGTHS.includes(length as BarerGeneratorLength)) {
		throw new ValidationError(
			`length must be one of: ${BARER_GENERATOR_SUPPORTED_LENGTHS.join(', ')}`,
			{
				length,
			},
		)
	}
	const format = options.format ?? 'base64url'
	if (!BARER_GENERATOR_SUPPORTED_FORMATS.includes(format as BarerGeneratorFormat)) {
		throw new ValidationError(
			`format must be one of: ${BARER_GENERATOR_SUPPORTED_FORMATS.join(', ')}`,
			{
				format,
			},
		)
	}
	const includeTimestamp = options.includeTimestamp ?? false
	const includeEntropy = options.includeEntropy ?? false
	if (typeof includeTimestamp !== 'boolean') {
		throw new ValidationError('includeTimestamp must be a boolean', { includeTimestamp })
	}
	if (typeof includeEntropy !== 'boolean') {
		throw new ValidationError('includeEntropy must be a boolean', { includeEntropy })
	}
	let prefix: string | undefined
	if (options.prefix !== undefined) {
		if (typeof options.prefix !== 'string') {
			throw new ValidationError('prefix must be a string', { prefix: options.prefix })
		}
		if (options.prefix.length > 20) {
			throw new ValidationError('prefix length must not exceed 20 characters', {
				prefixLength: options.prefix.length,
			})
		}
		if (!/^[a-zA-Z0-9_]+$/.test(options.prefix)) {
			throw new ValidationError(
				'prefix may only contain alphanumeric characters and underscores',
				{ prefix: options.prefix },
			)
		}
		prefix = options.prefix
	}
	return {
		count,
		length: length as BarerGeneratorLength,
		format: format as BarerGeneratorFormat,
		...(prefix !== undefined && { prefix }),
		includeTimestamp,
		includeEntropy,
	}
}
function barerGeneratorEncodeToken(bytes: Buffer, format: BarerGeneratorFormat): string {
	switch (format) {
		case 'base64url':
			return bytes.toString('base64url')
		case 'base64':
			return bytes.toString('base64').replace(/=+$/, '')
		case 'hex':
			return bytes.toString('hex')
		case 'alphanumeric':
			return barerGeneratorBase32Encode(bytes)
		default:
			throw new ValidationError(`Unsupported format: ${format}`, { format })
	}
}
function barerGeneratorCalculateEntropy(byteLength: number): number {
	if (byteLength <= 0) return 0
	const entropy = byteLength * 8
	return Math.round(entropy * 10) / 10
}
function barerGeneratorGetStrength(entropyBits: number): BarerGeneratorStrength {
	const threshold = BARER_GENERATOR_ENTROPY_THRESHOLDS.find(
		(t) => entropyBits >= t.min && entropyBits <= t.max,
	)
	return threshold?.label ?? 'weak'
}
function barerGeneratorGetPoolSize(format: BarerGeneratorFormat): number {
	switch (format) {
		case 'base64url':
		case 'base64':
			return 64
		case 'hex':
			return 16
		case 'alphanumeric':
			return 32
		default:
			return 64
	}
}
function barerGeneratorGenerateSingleToken(
	length: BarerGeneratorLength,
	format: BarerGeneratorFormat,
	prefix: string | undefined,
	includeTimestamp: boolean,
	includeEntropy: boolean,
): BarerGeneratorGeneratedToken {
	const bytes = randomBytes(length)
	const tokenRaw = barerGeneratorEncodeToken(bytes, format)
	const token = prefix ? `${prefix}_${tokenRaw}` : tokenRaw
	const timestamp = includeTimestamp ? Math.floor(Date.now() / 1000) : undefined
	const entropyBits = includeEntropy ? barerGeneratorCalculateEntropy(length) : undefined
	return {
		token,
		byteLength: length,
		format,
		...(prefix && { prefix }),
		...(timestamp !== undefined && { timestamp }),
		...(entropyBits !== undefined && { entropyBits }),
	}
}
function barerGeneratorBuildMetadata(
	validated: Required<Omit<BarerGeneratorGenerateOptions, 'prefix'>> & { prefix?: string },
	avgEntropyBits: number,
): BarerGeneratorGenerateMetadata {
	const poolSize = barerGeneratorGetPoolSize(validated.format)
	const strength = barerGeneratorGetStrength(avgEntropyBits)
	const base = {
		count: validated.count,
		length: validated.length,
		format: validated.format,
		includeTimestamp: validated.includeTimestamp,
		includeEntropy: validated.includeEntropy,
		poolSize,
		avgEntropyBits,
		strength,
	}
	if (validated.prefix) {
		return { ...base, prefix: validated.prefix }
	}
	return base
}
export function barerGeneratorGenerateTokens(
	options: BarerGeneratorGenerateOptions = {},
): BarerGeneratorGenerateResult {
	const validated = barerGeneratorValidateOptions(options)
	const tokens: BarerGeneratorGeneratedToken[] = []
	let totalEntropy = 0
	for (let i = 0; i < validated.count; i++) {
		const token = barerGeneratorGenerateSingleToken(
			validated.length,
			validated.format,
			validated.prefix,
			validated.includeTimestamp,
			validated.includeEntropy,
		)
		tokens.push(token)
		if (validated.includeEntropy && token.entropyBits !== undefined) {
			totalEntropy += token.entropyBits
		}
	}
	const avgEntropyBits = validated.includeEntropy
		? Math.round((totalEntropy / validated.count) * 10) / 10
		: barerGeneratorCalculateEntropy(validated.length)
	const metadata = barerGeneratorBuildMetadata(validated, avgEntropyBits)
	return {
		tokens: Object.freeze(tokens) as readonly BarerGeneratorGeneratedToken[],
		metadata: Object.freeze(metadata),
	}
}
export function barerGeneratorGenerateToken(
	options: BarerGeneratorGenerateOptions = {},
): BarerGeneratorGeneratedToken {
	const result = barerGeneratorGenerateTokens({ ...options, count: 1 })
	return result.tokens[0]!
}
export function barerGeneratorGenerateTokenString(
	options: BarerGeneratorGenerateOptions = {},
): string {
	const result = barerGeneratorGenerateTokens({ ...options, count: 1 })
	return result.tokens[0]?.token ?? ''
}
export function barerGeneratorGenerateSample(): BarerGeneratorGeneratedToken {
	return barerGeneratorGenerateTokens({
		count: 1,
		length: 32,
		format: 'base64url',
	}).tokens[0]!
}
export function barerGeneratorGenerateStrong(
	options: Partial<BarerGeneratorGenerateOptions> = {},
): BarerGeneratorGeneratedToken {
	return barerGeneratorGenerateTokens({
		count: 1,
		length: options.length ?? 64,
		format: options.format ?? 'base64url',
		includeEntropy: true,
		includeTimestamp: true,
		...options,
	}).tokens[0]!
}
export function barerGeneratorValidate(token: string): BarerGeneratorValidationResult {
	const errors: string[] = []
	const warnings: string[] = []
	if (!token || typeof token !== 'string') {
		return {
			isValid: false,
			strength: 'weak' as const,
			entropyBits: 0,
			length: 0,
			format: 'unknown' as const,
			errors: ['Token is empty or invalid'],
			warnings: [],
		}
	}
	const length = token.length
	if (length < 16) {
		errors.push('Token is too short (minimum 16 characters)')
	}
	if (length < 32) {
		warnings.push('Token length is below recommended (32 characters)')
	}
	let format: BarerGeneratorFormat | 'unknown' = 'unknown'
	if (/^[A-Za-z0-9_-]+$/.test(token)) {
		format = 'base64url'
	} else if (/^[A-Za-z0-9+/]+$/.test(token)) {
		format = 'base64'
	} else if (/^[0-9a-fA-F]+$/.test(token)) {
		format = 'hex'
	} else if (/^[A-Z2-7]+$/.test(token)) {
		format = 'alphanumeric'
	}
	const estimatedEntropy = length * 6
	const strength = barerGeneratorGetStrength(estimatedEntropy)
	if (strength === 'weak') {
		errors.push('Token strength is too weak')
	} else if (strength === 'medium') {
		warnings.push('Token strength could be improved')
	}
	return {
		isValid: errors.length === 0,
		strength,
		entropyBits: estimatedEntropy,
		length,
		format,
		errors: Object.freeze(errors),
		warnings: Object.freeze(warnings),
	}
}
export function barerGeneratorIsStrong(token: string, minEntropy: number = 128): boolean {
	const result = barerGeneratorValidate(token)
	return result.isValid && result.entropyBits >= minEntropy
}
export function barerGeneratorCalculateTokenEntropy(token: string): number {
	const length = token.length
	let poolSize = 64
	if (/^[0-9a-fA-F]+$/.test(token)) {
		poolSize = 16
	} else if (/^[A-Z2-7]+$/.test(token)) {
		poolSize = 32
	} else if (/^[A-Za-z0-9_-]+$/.test(token)) {
		poolSize = 64
	}
	return Math.round(length * Math.log2(poolSize) * 10) / 10
}
export function barerGeneratorExportTokens(
	result: BarerGeneratorGenerateResult,
	format: BarerGeneratorExportFormat = 'json',
): string {
	const { tokens, metadata } = result
	switch (format) {
		case 'json':
			return JSON.stringify({ metadata, tokens }, null, 2)
		case 'txt':
			return tokens.map((t) => t.token).join('\n')
		case 'csv': {
			const escapeCsv = (str: string): string => {
				if (str.includes('"') || str.includes(',') || str.includes('\n')) {
					return `"${str.replace(/"/g, '""')}"`
				}
				return str
			}
			const hasPrefix = metadata.prefix !== undefined
			const hasTimestamp = metadata.includeTimestamp
			const hasEntropy = metadata.includeEntropy
			const headers = ['token', 'byteLength', 'format']
			if (hasPrefix) headers.push('prefix')
			if (hasTimestamp) headers.push('timestamp')
			if (hasEntropy) headers.push('entropyBits')
			const rows = tokens.map((t) => {
				const cols = [escapeCsv(t.token), t.byteLength.toString(), t.format]
				if (hasPrefix && t.prefix) cols.push(escapeCsv(t.prefix))
				if (hasTimestamp && t.timestamp !== undefined) cols.push(t.timestamp.toString())
				if (hasEntropy && t.entropyBits !== undefined) cols.push(t.entropyBits.toString())
				return cols.join(',')
			})
			return headers.join(',') + '\n' + rows.join('\n')
		}
		default:
			throw new ValidationError(`Unsupported export format: ${format}`, { format })
	}
}
export function barerGeneratorExportToEnv(
	result: BarerGeneratorGenerateResult,
	prefix: string = 'BARER_GENERATOR_TOKEN',
): string {
	const { tokens } = result
	return tokens.map((t, i) => `${prefix}_${i + 1}="${t.token}"`).join('\n')
}
export class BarerGeneratorGenerator {
	private readonly options: Required<Omit<BarerGeneratorGenerateOptions, 'prefix'>> & {
		prefix?: string
	}
	private readonly entropyBits: number
	private readonly strength: BarerGeneratorStrength
	constructor(options: BarerGeneratorGenerateOptions = {}) {
		this.options = barerGeneratorValidateOptions(options)
		this.entropyBits = barerGeneratorCalculateEntropy(this.options.length)
		this.strength = barerGeneratorGetStrength(this.entropyBits)
	}
	public generate(): BarerGeneratorGenerateResult {
		const tokens: BarerGeneratorGeneratedToken[] = []
		let totalEntropy = 0
		for (let i = 0; i < this.options.count; i++) {
			const token = barerGeneratorGenerateSingleToken(
				this.options.length,
				this.options.format,
				this.options.prefix,
				this.options.includeTimestamp,
				this.options.includeEntropy,
			)
			tokens.push(token)
			if (this.options.includeEntropy && token.entropyBits !== undefined) {
				totalEntropy += token.entropyBits
			}
		}
		const avgEntropyBits = this.options.includeEntropy
			? Math.round((totalEntropy / this.options.count) * 10) / 10
			: this.entropyBits
		const metadata = barerGeneratorBuildMetadata(this.options, avgEntropyBits)
		return {
			tokens: Object.freeze(tokens) as readonly BarerGeneratorGeneratedToken[],
			metadata: Object.freeze(metadata),
		}
	}
	public generateOne(): string {
		const result = this.generate()
		return result.tokens[0]?.token ?? ''
	}
	public generateStrong(): BarerGeneratorGeneratedToken {
		const rawLength = Math.max(this.options.length, 64)
		const length: 16 | 32 | 64 | 128 =
			rawLength <= 16 ? 16 : rawLength <= 32 ? 32 : rawLength <= 64 ? 64 : 128
		return barerGeneratorGenerateStrong({
			length,
			format: this.options.format,
		})
	}
	public export(
		result: BarerGeneratorGenerateResult,
		format: BarerGeneratorExportFormat = 'json',
	): string {
		return barerGeneratorExportTokens(result, format)
	}
	public exportToEnv(
		result: BarerGeneratorGenerateResult,
		prefix: string = 'BARER_GENERATOR_TOKEN',
	): string {
		return barerGeneratorExportToEnv(result, prefix)
	}
	public validate(token: string): BarerGeneratorValidationResult {
		return barerGeneratorValidate(token)
	}
	public isStrong(token: string, minEntropy: number = 128): boolean {
		return barerGeneratorIsStrong(token, minEntropy)
	}
	public getEntropyBits(): number {
		return this.entropyBits
	}
	public getStrength(): BarerGeneratorStrength {
		return this.strength
	}
	public getOptions(): Readonly<
		Required<Omit<BarerGeneratorGenerateOptions, 'prefix'>> & {
			prefix?: string
		}
	> {
		return Object.freeze({ ...this.options })
	}
}
export const barerGeneratorPresets = Object.freeze({
	basic: {
		length: 16,
		format: 'base64url' as const,
		includeTimestamp: false,
		includeEntropy: false,
	} as BarerGeneratorGenerateOptions,
	standard: {
		length: 32,
		format: 'base64url' as const,
		includeTimestamp: true,
		includeEntropy: true,
	} as BarerGeneratorGenerateOptions,
	strong: {
		length: 64,
		format: 'base64url' as const,
		includeTimestamp: true,
		includeEntropy: true,
	} as BarerGeneratorGenerateOptions,
	maximum: {
		length: 128,
		format: 'hex' as const,
		includeTimestamp: true,
		includeEntropy: true,
	} as BarerGeneratorGenerateOptions,
	apiKey: {
		length: 32,
		format: 'alphanumeric' as const,
		includeTimestamp: false,
		includeEntropy: true,
	} as BarerGeneratorGenerateOptions,
	mobile: {
		length: 16,
		format: 'hex' as const,
		includeTimestamp: false,
		includeEntropy: false,
	} as BarerGeneratorGenerateOptions,
} as const)
export type BarerGeneratorPreset = keyof typeof barerGeneratorPresets
export function barerGeneratorGenerateWithPreset(
	preset: BarerGeneratorPreset,
	overrides: Partial<BarerGeneratorGenerateOptions> = {},
): BarerGeneratorGenerateResult {
	const baseOptions = barerGeneratorPresets[preset]
	return barerGeneratorGenerateTokens({ ...baseOptions, ...overrides })
}
