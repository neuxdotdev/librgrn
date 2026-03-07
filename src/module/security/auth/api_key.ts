import { randomBytes, randomUUID } from 'crypto'
import { ValidationError } from '../../../error.js'
export const API_KEY_GENERATOR_SUPPORTED_FORMATS = Object.freeze([
	'alphanumeric',
	'hex',
	'base64',
	'base64url',
	'uuid',
	'numeric',
] as const)
export const API_KEY_GENERATOR_EXPORT_FORMATS = Object.freeze([
	'json',
	'txt',
	'csv',
	'env',
] as const)
export const API_KEY_GENERATOR_ENTROPY_THRESHOLDS = Object.freeze([
	{ min: 0, max: 64, label: 'WEAK' as const, recommendation: 'Not recommended for production' },
	{ min: 65, max: 128, label: 'FAIR' as const, recommendation: 'Minimum for internal use' },
	{ min: 129, max: 192, label: 'GOOD' as const, recommendation: 'Recommended for most APIs' },
	{
		min: 193,
		max: 256,
		label: 'STRONG' as const,
		recommendation: 'Recommended for sensitive data',
	},
	{ min: 257, max: Infinity, label: 'VERY_STRONG' as const, recommendation: 'Maximum security' },
] as const)
export const API_KEY_GENERATOR_MIN_COUNT = 1 as const
export const API_KEY_GENERATOR_MAX_COUNT = 25 as const
export const API_KEY_GENERATOR_DEFAULT_COUNT = 1 as const
export const API_KEY_GENERATOR_MIN_LENGTH = 8 as const
export const API_KEY_GENERATOR_MAX_LENGTH = 256 as const
export const API_KEY_GENERATOR_DEFAULT_LENGTH = 32 as const
export const API_KEY_GENERATOR_SECURE_LENGTH = 64 as const
export const API_KEY_GENERATOR_MAX_PREFIX_LENGTH = 20 as const
export const API_KEY_GENERATOR_MIN_PREFIX_LENGTH = 1 as const
export const API_KEY_GENERATOR_RATE_LIMIT_WINDOW_MS = 60000 as const
export const API_KEY_GENERATOR_RATE_LIMIT_MAX_REQUESTS = 100 as const
export const API_KEY_GENERATOR_MAX_KEY_LENGTH = 4096 as const
export const API_KEY_GENERATOR_PREFIX_REGEX = /^[a-zA-Z][a-zA-Z0-9_]{0,19}$/
export const API_KEY_GENERATOR_BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
export const API_KEY_GENERATOR_FORBIDDEN_PREFIXES = Object.freeze([
	'api',
	'key',
	'secret',
	'token',
	'auth',
	'access',
	'private',
	'public',
] as const)
export const API_KEY_GENERATOR_MIN_ENTROPY_FOR_PRODUCTION = 193 as const
export const API_KEY_GENERATOR_MIN_ENTROPY_FOR_SENSITIVE = 256 as const
export type ApiKeyFormat = (typeof API_KEY_GENERATOR_SUPPORTED_FORMATS)[number]
export type ApiKeyExportFormat = (typeof API_KEY_GENERATOR_EXPORT_FORMATS)[number]
export type ApiKeyStrength = 'WEAK' | 'FAIR' | 'GOOD' | 'STRONG' | 'VERY_STRONG'
export type ApiKeySecurityLevel = 'low' | 'medium' | 'high' | 'critical'
export type ApiKeyPreset = 'basic' | 'standard' | 'secure' | 'maximum' | 'short' | 'long'
export interface ApiKeyGenerateOptions {
	readonly count?: number
	readonly length?: number
	readonly format?: ApiKeyFormat
	readonly prefix?: string | undefined
	readonly includeSecret?: boolean
	readonly secretLength?: number
	readonly secretFormat?: ApiKeyFormat
	readonly includeTimestamp?: boolean
	readonly includeEntropy?: boolean
	readonly securityLevel?: ApiKeySecurityLevel
}
export interface ApiKeyItem {
	readonly key: string
	readonly secret?: string | undefined
	readonly timestamp?: number | undefined
	readonly entropyBits?: number | undefined
	readonly strength?: ApiKeyStrength | undefined
}
export interface ApiKeyGenerateMetadata {
	readonly count: number
	readonly length: number
	readonly format: ApiKeyFormat
	readonly prefix?: string | undefined
	readonly includeSecret: boolean
	readonly secretLength?: number | undefined
	readonly secretFormat?: ApiKeyFormat | undefined
	readonly includeTimestamp: boolean
	readonly includeEntropy: boolean
	readonly entropyStrength: ApiKeyStrength
	readonly generatedAt: number
	readonly securityLevel: ApiKeySecurityLevel
	readonly byteLength: number
	readonly avgEntropyBits: number
}
export interface ApiKeyGenerateResult {
	readonly keys: readonly ApiKeyItem[]
	readonly metadata: ApiKeyGenerateMetadata
}
export interface ApiKeyValidationResult {
	readonly isValid: boolean
	readonly strength: ApiKeyStrength
	readonly entropyBits: number
	readonly length: number
	readonly format: ApiKeyFormat | 'unknown'
	readonly hasPrefix: boolean
	readonly prefix?: string | undefined
	readonly hasSecret: boolean
	readonly errors: readonly string[]
	readonly warnings: readonly string[]
	readonly securityScore: number
	readonly isProductionReady: boolean
}
export interface ApiKeyValidationOptions {
	readonly minEntropy?: number
	readonly requirePrefix?: boolean
	readonly requireSecret?: boolean
	readonly allowedFormats?: readonly ApiKeyFormat[]
	readonly checkProductionReady?: boolean
	readonly minLength?: number
}
export interface ApiKeyPresetConfig {
	readonly length: number
	readonly format: ApiKeyFormat
	readonly includeSecret: boolean
	readonly secretLength: number
	readonly secretFormat: ApiKeyFormat
	readonly includeTimestamp: boolean
	readonly includeEntropy: boolean
	readonly securityLevel: ApiKeySecurityLevel
}
export class ApiKeyValidationError extends ValidationError {
	constructor(message: string, context?: Record<string, unknown>) {
		super(message, { ...context, errorType: 'ApiKeyValidationError' })
	}
}
export class ApiKeySecurityError extends Error {
	constructor(message: string, context?: Record<string, unknown>) {
		super(message)
		this.name = 'ApiKeySecurityError'
		if (context) {
			;(this as any).context = context
		}
	}
}
export class ApiKeyRateLimitError extends Error {
	constructor(message: string, context?: Record<string, unknown>) {
		super(message)
		this.name = 'ApiKeyRateLimitError'
		if (context) {
			;(this as any).context = context
		}
	}
}
function assertIsNumber(value: unknown, fieldName: string): number {
	if (typeof value !== 'number' || !Number.isFinite(value)) {
		throw new ApiKeyValidationError(`${fieldName} must be a finite number`, {
			fieldName,
			value,
		})
	}
	return value
}
function assertIsInteger(value: number, fieldName: string): number {
	if (!Number.isInteger(value)) {
		throw new ApiKeyValidationError(`${fieldName} must be an integer`, { fieldName, value })
	}
	return value
}
function assertIsBoolean(value: unknown, fieldName: string): boolean {
	if (typeof value !== 'boolean') {
		throw new ApiKeyValidationError(`${fieldName} must be a boolean`, { fieldName, value })
	}
	return value
}
function assertIsString(value: unknown, fieldName: string): string {
	if (typeof value !== 'string') {
		throw new ApiKeyValidationError(`${fieldName} must be a string`, { fieldName, value })
	}
	return value
}
function assertInArray<T>(value: T, allowedValues: readonly T[], fieldName: string): T {
	if (!allowedValues.includes(value)) {
		throw new ApiKeyValidationError(
			`${fieldName} must be one of: ${allowedValues.join(', ')}`,
			{ fieldName, value, allowedValues },
		)
	}
	return value
}
function sanitizeString(value: string): string {
	return value.trim().normalize('NFC')
}
function apiKeyGeneratorBase32Encode(buffer: Buffer): string {
	if (!Buffer.isBuffer(buffer)) {
		throw new ApiKeyValidationError('Input must be a Buffer', { type: typeof buffer })
	}
	if (buffer.length === 0) {
		throw new ApiKeyValidationError('Buffer cannot be empty', { length: buffer.length })
	}
	let bits = 0
	let value = 0
	let output = ''
	for (let i = 0; i < buffer.length; i++) {
		const byte = buffer[i]!
		value = (value << 8) | byte
		bits += 8
		while (bits >= 5) {
			const index = (value >>> (bits - 5)) & 31
			output += API_KEY_GENERATOR_BASE32_ALPHABET[index]
			bits -= 5
		}
	}
	if (bits > 0) {
		const index = (value << (5 - bits)) & 31
		output += API_KEY_GENERATOR_BASE32_ALPHABET[index]
	}
	return output
}
function apiKeyGeneratorGenerateNumericString(length: number): string {
	if (length <= 0) {
		throw new ApiKeyValidationError('Numeric length must be positive', { length })
	}
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
const apiKeyGeneratorGenerators: Record<ApiKeyFormat, (length: number) => string> = {
	alphanumeric: (len) => {
		if (len <= 0) throw new ApiKeyValidationError('Length must be positive', { length: len })
		return apiKeyGeneratorBase32Encode(randomBytes(Math.ceil(len * 0.625)))
	},
	hex: (len) => {
		if (len <= 0) throw new ApiKeyValidationError('Length must be positive', { length: len })
		return randomBytes(Math.ceil(len / 2))
			.toString('hex')
			.slice(0, len)
	},
	base64: (len) => {
		if (len <= 0) throw new ApiKeyValidationError('Length must be positive', { length: len })
		return randomBytes(Math.ceil(len * 0.75))
			.toString('base64')
			.replace(/=+$/, '')
			.slice(0, len)
	},
	base64url: (len) => {
		if (len <= 0) throw new ApiKeyValidationError('Length must be positive', { length: len })
		return randomBytes(Math.ceil(len * 0.75))
			.toString('base64url')
			.slice(0, len)
	},
	uuid: () => randomUUID(),
	numeric: (len) => {
		if (len <= 0) throw new ApiKeyValidationError('Length must be positive', { length: len })
		return apiKeyGeneratorGenerateNumericString(len)
	},
}
function validateCount(count: unknown): number {
	const value = assertIsInteger(assertIsNumber(count, 'count'), 'count')
	if (value < API_KEY_GENERATOR_MIN_COUNT) {
		throw new ApiKeyValidationError(`count must be at least ${API_KEY_GENERATOR_MIN_COUNT}`, {
			count: value,
			minimum: API_KEY_GENERATOR_MIN_COUNT,
		})
	}
	if (value > API_KEY_GENERATOR_MAX_COUNT) {
		throw new ApiKeyValidationError(
			`count must not exceed ${API_KEY_GENERATOR_MAX_COUNT} (rate limit protection)`,
			{ count: value, maximum: API_KEY_GENERATOR_MAX_COUNT },
		)
	}
	return value
}
function validateLength(length: unknown): number {
	const value = assertIsInteger(assertIsNumber(length, 'length'), 'length')
	if (value < API_KEY_GENERATOR_MIN_LENGTH) {
		throw new ApiKeyValidationError(`length must be at least ${API_KEY_GENERATOR_MIN_LENGTH}`, {
			length: value,
			minimum: API_KEY_GENERATOR_MIN_LENGTH,
		})
	}
	if (value > API_KEY_GENERATOR_MAX_LENGTH) {
		throw new ApiKeyValidationError(`length must not exceed ${API_KEY_GENERATOR_MAX_LENGTH}`, {
			length: value,
			maximum: API_KEY_GENERATOR_MAX_LENGTH,
		})
	}
	return value
}
function validateFormat(format: unknown): ApiKeyFormat {
	const value = assertInArray(
		assertIsString(format, 'format'),
		API_KEY_GENERATOR_SUPPORTED_FORMATS,
		'format',
	)
	return value as ApiKeyFormat
}
function validatePrefix(prefix: unknown): string | undefined {
	if (prefix === undefined || prefix === null) {
		return undefined
	}
	const value = sanitizeString(assertIsString(prefix, 'prefix'))
	if (value.length === 0) {
		return undefined
	}
	if (value.length < API_KEY_GENERATOR_MIN_PREFIX_LENGTH) {
		throw new ApiKeyValidationError(
			`prefix must be at least ${API_KEY_GENERATOR_MIN_PREFIX_LENGTH} character`,
			{ prefixLength: value.length, minimum: API_KEY_GENERATOR_MIN_PREFIX_LENGTH },
		)
	}
	if (value.length > API_KEY_GENERATOR_MAX_PREFIX_LENGTH) {
		throw new ApiKeyValidationError(
			`prefix must not exceed ${API_KEY_GENERATOR_MAX_PREFIX_LENGTH} characters`,
			{ prefixLength: value.length, maximum: API_KEY_GENERATOR_MAX_PREFIX_LENGTH },
		)
	}
	if (!API_KEY_GENERATOR_PREFIX_REGEX.test(value)) {
		throw new ApiKeyValidationError(
			'prefix must start with a letter and contain only alphanumeric characters and underscores',
			{ prefix: value, pattern: API_KEY_GENERATOR_PREFIX_REGEX.source },
		)
	}
	if (API_KEY_GENERATOR_FORBIDDEN_PREFIXES.some((fp) => value.toLowerCase().startsWith(fp))) {
		throw new ApiKeySecurityError(
			`prefix cannot start with reserved words: ${API_KEY_GENERATOR_FORBIDDEN_PREFIXES.join(', ')}`,
			{ prefix: value, forbiddenPrefixes: API_KEY_GENERATOR_FORBIDDEN_PREFIXES },
		)
	}
	return value
}
function validateSecurityLevel(level: unknown): ApiKeySecurityLevel {
	const allowedLevels: readonly ApiKeySecurityLevel[] = ['low', 'medium', 'high', 'critical']
	const value = assertInArray(
		assertIsString(level, 'securityLevel'),
		allowedLevels,
		'securityLevel',
	)
	return value as ApiKeySecurityLevel
}
function apiKeyGeneratorValidateOptions(
	options: ApiKeyGenerateOptions,
): Required<Omit<ApiKeyGenerateOptions, 'prefix'>> & { prefix?: string } {
	const count = validateCount(options.count ?? API_KEY_GENERATOR_DEFAULT_COUNT)
	const length = validateLength(options.length ?? API_KEY_GENERATOR_DEFAULT_LENGTH)
	const format = validateFormat(options.format ?? 'alphanumeric')
	const prefix = validatePrefix(options.prefix)
	const includeSecret = assertIsBoolean(options.includeSecret ?? false, 'includeSecret')
	const secretLength = validateLength(options.secretLength ?? length)
	const secretFormat = validateFormat(options.secretFormat ?? format)
	const includeTimestamp = assertIsBoolean(options.includeTimestamp ?? false, 'includeTimestamp')
	const includeEntropy = assertIsBoolean(options.includeEntropy ?? false, 'includeEntropy')
	const securityLevel = validateSecurityLevel(options.securityLevel ?? 'medium')
	if (securityLevel === 'critical' && length < API_KEY_GENERATOR_SECURE_LENGTH) {
		throw new ApiKeySecurityError(
			`Critical security level requires minimum ${API_KEY_GENERATOR_SECURE_LENGTH} characters`,
			{ securityLevel, length, required: API_KEY_GENERATOR_SECURE_LENGTH },
		)
	}
	if (securityLevel === 'high' && length < 32) {
		throw new ApiKeySecurityError('High security level requires minimum 32 characters', {
			securityLevel,
			length,
			required: 32,
		})
	}
	if (includeSecret && secretLength < API_KEY_GENERATOR_MIN_LENGTH) {
		throw new ApiKeyValidationError(
			`secretLength must be at least ${API_KEY_GENERATOR_MIN_LENGTH}`,
			{ secretLength, minimum: API_KEY_GENERATOR_MIN_LENGTH },
		)
	}
	return {
		count,
		length,
		format,
		...(prefix !== undefined ? { prefix } : {}),
		includeSecret,
		secretLength,
		secretFormat,
		includeTimestamp,
		includeEntropy,
		securityLevel,
	}
}
export function apiKeyGeneratorCalculateEntropyBits(length: number, format: ApiKeyFormat): number {
	if (length <= 0) return 0
	let poolSize = 0
	switch (format) {
		case 'alphanumeric':
			poolSize = 32
			break
		case 'hex':
			poolSize = 16
			break
		case 'base64':
		case 'base64url':
			poolSize = 64
			break
		case 'uuid':
			return 122
		case 'numeric':
			poolSize = 10
			break
	}
	const entropy = length * Math.log2(poolSize)
	return Math.round(entropy * 10) / 10
}
export function apiKeyGeneratorGetStrength(entropyBits: number): ApiKeyStrength {
	if (!Number.isFinite(entropyBits)) {
		return 'WEAK'
	}
	const threshold = API_KEY_GENERATOR_ENTROPY_THRESHOLDS.find(
		(t) => entropyBits >= t.min && entropyBits <= t.max,
	)
	return threshold?.label ?? 'WEAK'
}
export function apiKeyGeneratorGetSecurityLevel(entropyBits: number): ApiKeySecurityLevel {
	if (entropyBits >= API_KEY_GENERATOR_MIN_ENTROPY_FOR_SENSITIVE) {
		return 'critical'
	}
	if (entropyBits >= API_KEY_GENERATOR_MIN_ENTROPY_FOR_PRODUCTION) {
		return 'high'
	}
	if (entropyBits >= 128) {
		return 'medium'
	}
	return 'low'
}
export function apiKeyGeneratorGetPoolSize(format: ApiKeyFormat): number {
	switch (format) {
		case 'alphanumeric':
			return 32
		case 'hex':
			return 16
		case 'base64':
		case 'base64url':
			return 64
		case 'uuid':
			return 2
		case 'numeric':
			return 10
	}
}
export function apiKeyGeneratorCalculateSecurityScore(validation: ApiKeyValidationResult): number {
	let score = 0
	score += Math.min(40, (validation.entropyBits / 256) * 40)
	if (validation.format !== 'unknown') {
		score += 20
	}
	if (validation.errors.length === 0) {
		score += 25
	}
	if (validation.warnings.length === 0) {
		score += 15
	}
	return Math.round(score)
}
function apiKeyGeneratorGenerateSingleItem(
	validated: Required<Omit<ApiKeyGenerateOptions, 'prefix'>> & { prefix?: string },
): ApiKeyItem {
	const generator = apiKeyGeneratorGenerators[validated.format]
	if (!generator) {
		throw new ApiKeyValidationError('Unsupported format generator', {
			format: validated.format,
		})
	}
	let keyRaw: string
	if (validated.format === 'uuid') {
		keyRaw = generator(0)
	} else {
		keyRaw = generator(validated.length)
	}
	if (!keyRaw || keyRaw.length === 0) {
		throw new ApiKeySecurityError('Generated key is empty', { format: validated.format })
	}
	const totalKeyLength = validated.prefix
		? validated.prefix.length + 1 + keyRaw.length
		: keyRaw.length
	if (totalKeyLength > API_KEY_GENERATOR_MAX_KEY_LENGTH) {
		throw new ApiKeySecurityError('Generated key exceeds maximum length', {
			length: totalKeyLength,
			maximum: API_KEY_GENERATOR_MAX_KEY_LENGTH,
		})
	}
	const key = validated.prefix ? `${validated.prefix}_${keyRaw}` : keyRaw
	const item: {
		key: string
		secret?: string
		timestamp?: number
		entropyBits?: number
		strength?: ApiKeyStrength
	} = { key }
	if (validated.includeSecret) {
		const secretGenerator = apiKeyGeneratorGenerators[validated.secretFormat]
		let secretRaw: string
		if (validated.secretFormat === 'uuid') {
			secretRaw = secretGenerator(0)
		} else {
			secretRaw = secretGenerator(validated.secretLength)
		}
		item.secret = validated.prefix ? `${validated.prefix}_${secretRaw}` : secretRaw
	}
	if (validated.includeTimestamp) {
		item.timestamp = Math.floor(Date.now() / 1000)
	}
	if (validated.includeEntropy) {
		item.entropyBits = apiKeyGeneratorCalculateEntropyBits(validated.length, validated.format)
		item.strength = apiKeyGeneratorGetStrength(item.entropyBits)
	}
	return item as ApiKeyItem
}
function apiKeyGeneratorBuildMetadata(
	validated: Required<Omit<ApiKeyGenerateOptions, 'prefix'>> & { prefix?: string },
	avgEntropyBits: number,
): ApiKeyGenerateMetadata {
	const byteLength = validated.format === 'uuid' ? 16 : Math.ceil(validated.length / 2)
	const entropyStrength = apiKeyGeneratorGetStrength(avgEntropyBits)
	const securityLevel = apiKeyGeneratorGetSecurityLevel(avgEntropyBits)
	const base = {
		count: validated.count,
		length: validated.length,
		format: validated.format,
		includeSecret: validated.includeSecret,
		includeTimestamp: validated.includeTimestamp,
		includeEntropy: validated.includeEntropy,
		entropyStrength,
		generatedAt: Math.floor(Date.now() / 1000),
		securityLevel,
		byteLength,
		avgEntropyBits,
	}
	return {
		...base,
		...(validated.prefix !== undefined ? { prefix: validated.prefix } : {}),
		...(validated.includeSecret
			? { secretLength: validated.secretLength, secretFormat: validated.secretFormat }
			: {}),
	}
}
export function apiKeyGeneratorDetectFormat(key: string): ApiKeyFormat | 'unknown' {
	if (!key || typeof key !== 'string') {
		return 'unknown'
	}
	const keyWithoutPrefix = key.includes('_') ? key.split('_').slice(1).join('_') : key
	if (!keyWithoutPrefix || keyWithoutPrefix.length === 0) {
		return 'unknown'
	}
	if (
		/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
			keyWithoutPrefix,
		)
	) {
		return 'uuid'
	}
	if (/^[0-9a-fA-F]+$/.test(keyWithoutPrefix)) {
		return 'hex'
	}
	if (/^[0-9]+$/.test(keyWithoutPrefix)) {
		return 'numeric'
	}
	if (/^[A-Za-z0-9_-]+$/.test(keyWithoutPrefix)) {
		return 'base64url'
	}
	if (/^[A-Za-z0-9+/]+$/.test(keyWithoutPrefix)) {
		return 'base64'
	}
	if (/^[A-Z2-7]+$/.test(keyWithoutPrefix)) {
		return 'alphanumeric'
	}
	return 'unknown'
}
export function apiKeyGeneratorExtractPrefix(key: string): string | undefined {
	if (!key || typeof key !== 'string') {
		return undefined
	}
	if (!key.includes('_')) {
		return undefined
	}
	const parts = key.split('_')
	if (parts.length === 0 || !parts[0]) {
		return undefined
	}
	const potentialPrefix = parts[0]
	return potentialPrefix && API_KEY_GENERATOR_PREFIX_REGEX.test(potentialPrefix)
		? potentialPrefix
		: undefined
}
export function apiKeyGeneratorGenerateTokens(
	options: ApiKeyGenerateOptions = {},
): ApiKeyGenerateResult {
	const validated = apiKeyGeneratorValidateOptions(options)
	const keys: ApiKeyItem[] = []
	let totalEntropy = 0
	for (let i = 0; i < validated.count; i++) {
		const key = apiKeyGeneratorGenerateSingleItem(validated)
		keys.push(key)
		if (validated.includeEntropy && key.entropyBits !== undefined) {
			totalEntropy += key.entropyBits
		}
	}
	const avgEntropyBits = validated.includeEntropy
		? Math.round((totalEntropy / validated.count) * 10) / 10
		: apiKeyGeneratorCalculateEntropyBits(validated.length, validated.format)
	const metadata = apiKeyGeneratorBuildMetadata(validated, avgEntropyBits)
	return {
		keys: Object.freeze(keys) as readonly ApiKeyItem[],
		metadata: Object.freeze(metadata),
	}
}
export function apiKeyGeneratorGenerateToken(options: ApiKeyGenerateOptions = {}): ApiKeyItem {
	const result = apiKeyGeneratorGenerateTokens({ ...options, count: 1 })
	const key = result.keys[0]
	if (!key) {
		throw new ApiKeySecurityError('Failed to generate key - keys array is empty')
	}
	return key
}
export function apiKeyGeneratorGenerateKeyString(options: ApiKeyGenerateOptions = {}): string {
	const key = apiKeyGeneratorGenerateToken({ ...options, count: 1 })
	return key.key
}
export function apiKeyGeneratorGenerateSample(): ApiKeyItem {
	return apiKeyGeneratorGenerateTokens({
		count: 1,
		length: 32,
		format: 'alphanumeric',
	}).keys[0]!
}
export function apiKeyGeneratorGenerateBasic(count: number = 1): ApiKeyGenerateResult {
	return apiKeyGeneratorGenerateTokens({
		count,
		length: 32,
		format: 'alphanumeric',
		securityLevel: 'low',
	})
}
export function apiKeyGeneratorGenerateStandard(count: number = 1): ApiKeyGenerateResult {
	return apiKeyGeneratorGenerateTokens({
		count,
		length: 64,
		format: 'base64url',
		includeSecret: true,
		secretLength: 64,
		securityLevel: 'medium',
	})
}
export function apiKeyGeneratorGenerateSecure(count: number = 1): ApiKeyGenerateResult {
	return apiKeyGeneratorGenerateTokens({
		count,
		length: 64,
		format: 'base64url',
		includeSecret: true,
		secretLength: 64,
		includeTimestamp: true,
		includeEntropy: true,
		securityLevel: 'high',
	})
}
export function apiKeyGeneratorGenerateMaximum(count: number = 1): ApiKeyGenerateResult {
	return apiKeyGeneratorGenerateTokens({
		count,
		length: 128,
		format: 'hex',
		includeSecret: true,
		secretLength: 128,
		includeTimestamp: true,
		includeEntropy: true,
		securityLevel: 'critical',
	})
}
export function apiKeyGeneratorValidate(
	key: string,
	validationOptions?: ApiKeyValidationOptions,
): ApiKeyValidationResult {
	const errors: string[] = []
	const warnings: string[] = []
	if (!key || typeof key !== 'string') {
		return {
			isValid: false,
			strength: 'WEAK',
			entropyBits: 0,
			length: 0,
			format: 'unknown',
			hasPrefix: false,
			errors: Object.freeze(['Key is empty or invalid']) as readonly string[],
			warnings: Object.freeze([]) as readonly string[],
			securityScore: 0,
			isProductionReady: false,
			hasSecret: false,
		}
	}
	if (key.length > API_KEY_GENERATOR_MAX_KEY_LENGTH) {
		errors.push(`Key exceeds maximum length (${API_KEY_GENERATOR_MAX_KEY_LENGTH} characters)`)
	}
	if (key.length < 20) {
		warnings.push('Key is unusually short')
	}
	const format = apiKeyGeneratorDetectFormat(key)
	const prefix = apiKeyGeneratorExtractPrefix(key)
	const hasPrefix = prefix !== undefined
	const keyWithoutPrefix = hasPrefix ? key.split('_').slice(1).join('_') : key
	const keyLength = keyWithoutPrefix.length
	const hasSecret = false
	if (
		validationOptions?.allowedFormats &&
		!validationOptions.allowedFormats.includes(format as ApiKeyFormat)
	) {
		errors.push(`Key format '${format}' is not in allowed formats`)
	}
	if (validationOptions?.requirePrefix && !hasPrefix) {
		errors.push('Key is required to have a prefix')
	}
	if (validationOptions?.minLength && keyLength < validationOptions.minLength) {
		errors.push(
			`Key length (${keyLength}) is below minimum required (${validationOptions.minLength})`,
		)
	}
	const entropyBits = apiKeyGeneratorCalculateEntropyBits(keyLength, format as ApiKeyFormat)
	const strength = apiKeyGeneratorGetStrength(entropyBits)
	if (validationOptions?.minEntropy && entropyBits < validationOptions.minEntropy) {
		errors.push(
			`Key entropy (${entropyBits}) is below minimum required (${validationOptions.minEntropy})`,
		)
	}
	if (strength === 'WEAK') {
		errors.push('Key strength is too weak')
	} else if (strength === 'FAIR') {
		warnings.push('Key strength could be improved')
	}
	const isProductionReady =
		errors.length === 0 && entropyBits >= API_KEY_GENERATOR_MIN_ENTROPY_FOR_PRODUCTION
	if (validationOptions?.checkProductionReady && !isProductionReady) {
		errors.push('Key is not production-ready')
	}
	const baseResult = {
		isValid: errors.length === 0,
		strength,
		entropyBits,
		length: keyLength,
		format,
		hasPrefix,
		hasSecret,
		errors: Object.freeze(errors) as readonly string[],
		warnings: Object.freeze(warnings) as readonly string[],
	}
	const securityScore = apiKeyGeneratorCalculateSecurityScore(
		baseResult as ApiKeyValidationResult,
	)
	return {
		...baseResult,
		securityScore,
		isProductionReady,
		...(prefix !== undefined ? { prefix } : {}),
	}
}
export function apiKeyGeneratorIsStrong(
	key: string,
	minEntropy: number = API_KEY_GENERATOR_MIN_ENTROPY_FOR_PRODUCTION,
): boolean {
	const validation = apiKeyGeneratorValidate(key)
	return validation.isValid && validation.entropyBits >= minEntropy
}
export function apiKeyGeneratorIsProductionReady(key: string): boolean {
	const validation = apiKeyGeneratorValidate(key, { checkProductionReady: true })
	return validation.isProductionReady
}
export function apiKeyGeneratorCalculateEntropyFromKey(key: string): number {
	return apiKeyGeneratorValidate(key).entropyBits
}
export function apiKeyGeneratorExportTokens(
	result: ApiKeyGenerateResult,
	exportFormat: ApiKeyExportFormat = 'json',
): string {
	const { keys, metadata } = result
	if (!keys || keys.length === 0) {
		throw new ApiKeyValidationError('No keys to export', { keyCount: 0 })
	}
	switch (exportFormat) {
		case 'json':
			return JSON.stringify({ metadata, keys }, null, 2)
		case 'txt': {
			return keys
				.map((item) => {
					const lines = [`key: ${item.key}`]
					if (item.secret) lines.push(`secret: ${item.secret}`)
					if (item.timestamp) lines.push(`timestamp: ${item.timestamp}`)
					if (item.entropyBits) lines.push(`entropy: ${item.entropyBits} bits`)
					return lines.join('\n')
				})
				.join('\n\n')
		}
		case 'csv': {
			const hasSecret = keys.some((item) => item.secret !== undefined)
			const escapeCsv = (str: string): string => {
				if (str.includes('"') || str.includes(',') || str.includes('\n')) {
					return `"${str.replace(/"/g, '""')}"`
				}
				return str
			}
			const headers = ['key']
			if (hasSecret) headers.push('secret')
			if (metadata.includeTimestamp) headers.push('timestamp')
			if (metadata.includeEntropy) headers.push('entropyBits')
			const rows = keys.map((item) => {
				const cols = [escapeCsv(item.key)]
				if (hasSecret) cols.push(item.secret ? escapeCsv(item.secret) : '')
				if (metadata.includeTimestamp && item.timestamp !== undefined) {
					cols.push(item.timestamp.toString())
				}
				if (metadata.includeEntropy && item.entropyBits !== undefined) {
					cols.push(item.entropyBits.toString())
				}
				return cols.join(',')
			})
			return [headers.join(','), ...rows].join('\n')
		}
		case 'env': {
			const envPrefix = 'API_KEY'
			return keys
				.map((item, i) => {
					const lines = [`${envPrefix}_${i + 1}="${item.key}"`]
					if (item.secret) lines.push(`${envPrefix}_${i + 1}_SECRET="${item.secret}"`)
					return lines.join('\n')
				})
				.join('\n')
		}
		default:
			throw new ApiKeyValidationError(`Unsupported export format: ${exportFormat}`, {
				exportFormat,
			})
	}
}
export function apiKeyGeneratorExportToEnv(
	result: ApiKeyGenerateResult,
	prefix: string = 'API_KEY',
): string {
	if (!prefix || prefix.trim().length === 0) {
		throw new ApiKeyValidationError('Environment variable prefix cannot be empty')
	}
	if (!/^[A-Z][A-Z0-9_]*$/.test(prefix)) {
		throw new ApiKeyValidationError(
			'Environment variable prefix must be uppercase alphanumeric with underscores',
		)
	}
	const { keys } = result
	return keys
		.map((item, i) => {
			const lines = [`${prefix}_${i + 1}="${item.key}"`]
			if (item.secret) lines.push(`${prefix}_${i + 1}_SECRET="${item.secret}"`)
			return lines.join('\n')
		})
		.join('\n')
}
export const apiKeyGeneratorPresets = Object.freeze({
	basic: {
		length: 32,
		format: 'alphanumeric' as ApiKeyFormat,
		includeSecret: false,
		secretLength: 32,
		secretFormat: 'alphanumeric' as ApiKeyFormat,
		includeTimestamp: false,
		includeEntropy: false,
		securityLevel: 'low' as ApiKeySecurityLevel,
	},
	standard: {
		length: 64,
		format: 'base64url' as ApiKeyFormat,
		includeSecret: true,
		secretLength: 64,
		secretFormat: 'base64url' as ApiKeyFormat,
		includeTimestamp: true,
		includeEntropy: true,
		securityLevel: 'medium' as ApiKeySecurityLevel,
	},
	secure: {
		length: 64,
		format: 'base64url' as ApiKeyFormat,
		includeSecret: true,
		secretLength: 64,
		secretFormat: 'base64url' as ApiKeyFormat,
		includeTimestamp: true,
		includeEntropy: true,
		securityLevel: 'high' as ApiKeySecurityLevel,
	},
	maximum: {
		length: 128,
		format: 'hex' as ApiKeyFormat,
		includeSecret: true,
		secretLength: 128,
		secretFormat: 'hex' as ApiKeyFormat,
		includeTimestamp: true,
		includeEntropy: true,
		securityLevel: 'critical' as ApiKeySecurityLevel,
	},
	short: {
		length: 32,
		format: 'hex' as ApiKeyFormat,
		includeSecret: false,
		secretLength: 32,
		secretFormat: 'hex' as ApiKeyFormat,
		includeTimestamp: true,
		includeEntropy: false,
		securityLevel: 'low' as ApiKeySecurityLevel,
	},
	long: {
		length: 128,
		format: 'base64url' as ApiKeyFormat,
		includeSecret: true,
		secretLength: 128,
		secretFormat: 'base64url' as ApiKeyFormat,
		includeTimestamp: true,
		includeEntropy: true,
		securityLevel: 'high' as ApiKeySecurityLevel,
	},
} as const satisfies Record<ApiKeyPreset, ApiKeyPresetConfig>)
export function apiKeyGeneratorGenerateWithPreset(
	preset: ApiKeyPreset,
	overrides: Partial<ApiKeyGenerateOptions> = {},
): ApiKeyGenerateResult {
	const baseOptions = apiKeyGeneratorPresets[preset]
	if (!baseOptions) {
		throw new ApiKeyValidationError(`Unknown preset: ${preset}`, {
			preset,
			availablePresets: Object.keys(apiKeyGeneratorPresets),
		})
	}
	return apiKeyGeneratorGenerateTokens({ ...baseOptions, ...overrides })
}
export function apiKeyGeneratorGetLengthStrength(
	length: number,
	format: ApiKeyFormat,
): ApiKeyStrength {
	const entropyBits = apiKeyGeneratorCalculateEntropyBits(length, format)
	return apiKeyGeneratorGetStrength(entropyBits)
}
export function apiKeyGeneratorCompareLengths(
	len1: number,
	len2: number,
	format: ApiKeyFormat,
): number {
	const strength1 = apiKeyGeneratorGetLengthStrength(len1, format)
	const strength2 = apiKeyGeneratorGetLengthStrength(len2, format)
	const strengthOrder: Record<ApiKeyStrength, number> = {
		WEAK: 0,
		FAIR: 1,
		GOOD: 2,
		STRONG: 3,
		VERY_STRONG: 4,
	}
	return strengthOrder[strength2] - strengthOrder[strength1]
}
export function apiKeyGeneratorIsLengthSecure(
	length: number,
	format: ApiKeyFormat,
	minStrength: ApiKeyStrength = 'GOOD',
): boolean {
	const strength = apiKeyGeneratorGetLengthStrength(length, format)
	const strengthOrder: Record<ApiKeyStrength, number> = {
		WEAK: 0,
		FAIR: 1,
		GOOD: 2,
		STRONG: 3,
		VERY_STRONG: 4,
	}
	return strengthOrder[strength] >= strengthOrder[minStrength]
}
export function apiKeyGeneratorGetRecommendedLength(securityLevel: ApiKeySecurityLevel): number {
	switch (securityLevel) {
		case 'critical':
			return 128
		case 'high':
			return 64
		case 'medium':
			return 64
		case 'low':
			return 32
		default:
			return 64
	}
}
export function apiKeyGeneratorGetSecurityReport(key: string): {
	readonly score: number
	readonly strength: ApiKeyStrength
	readonly isProductionReady: boolean
	readonly recommendations: readonly string[]
} {
	const validation = apiKeyGeneratorValidate(key)
	const recommendations: string[] = []
	if (validation.entropyBits < API_KEY_GENERATOR_MIN_ENTROPY_FOR_PRODUCTION) {
		recommendations.push('Increase key length for production use (minimum 64 characters)')
	}
	if (validation.length < 32) {
		recommendations.push('Use minimum 32 characters for better security')
	}
	if (validation.format === 'unknown') {
		recommendations.push('Use a standard encoding format (base64url, hex, etc.)')
	}
	if (validation.format === 'numeric') {
		recommendations.push('Consider using alphanumeric or base64 format for higher entropy')
	}
	if (validation.warnings.length > 0) {
		recommendations.push(`Address ${validation.warnings.length} warning(s)`)
	}
	return {
		score: validation.securityScore,
		strength: validation.strength,
		isProductionReady: validation.isProductionReady,
		recommendations: Object.freeze(recommendations) as readonly string[],
	}
}
export class ApiKeyGenerator {
	private readonly options: Required<Omit<ApiKeyGenerateOptions, 'prefix'>> & { prefix?: string }
	private readonly entropyBits: number
	private readonly strength: ApiKeyStrength
	private readonly securityLevel: ApiKeySecurityLevel
	private static requestCount = 0
	private static lastRequestTime = 0
	constructor(options: ApiKeyGenerateOptions = {}) {
		this.options = apiKeyGeneratorValidateOptions(options)
		this.entropyBits = apiKeyGeneratorCalculateEntropyBits(
			this.options.length,
			this.options.format,
		)
		this.strength = apiKeyGeneratorGetStrength(this.entropyBits)
		this.securityLevel = this.options.securityLevel
	}
	private static checkRateLimit(): void {
		const now = Date.now()
		if (now - ApiKeyGenerator.lastRequestTime > API_KEY_GENERATOR_RATE_LIMIT_WINDOW_MS) {
			ApiKeyGenerator.requestCount = 0
			ApiKeyGenerator.lastRequestTime = now
		}
		if (ApiKeyGenerator.requestCount >= API_KEY_GENERATOR_RATE_LIMIT_MAX_REQUESTS) {
			throw new ApiKeyRateLimitError(
				`Rate limit exceeded: ${API_KEY_GENERATOR_RATE_LIMIT_MAX_REQUESTS} requests per minute`,
			)
		}
		ApiKeyGenerator.requestCount++
	}
	public generate(): ApiKeyGenerateResult {
		ApiKeyGenerator.checkRateLimit()
		const keys: ApiKeyItem[] = []
		let totalEntropy = 0
		for (let i = 0; i < this.options.count; i++) {
			const key = apiKeyGeneratorGenerateSingleItem(this.options)
			keys.push(key)
			if (this.options.includeEntropy && key.entropyBits !== undefined) {
				totalEntropy += key.entropyBits
			}
		}
		const avgEntropyBits = this.options.includeEntropy
			? Math.round((totalEntropy / this.options.count) * 10) / 10
			: this.entropyBits
		const metadata = apiKeyGeneratorBuildMetadata(this.options, avgEntropyBits)
		return {
			keys: Object.freeze(keys) as readonly ApiKeyItem[],
			metadata: Object.freeze(metadata),
		}
	}
	public generateOne(): string {
		const result = this.generate()
		return result.keys[0]?.key ?? ''
	}
	public generateBasic(count: number = 1): ApiKeyGenerateResult {
		return apiKeyGeneratorGenerateBasic(count)
	}
	public generateStandard(count: number = 1): ApiKeyGenerateResult {
		return apiKeyGeneratorGenerateStandard(count)
	}
	public generateSecure(count: number = 1): ApiKeyGenerateResult {
		return apiKeyGeneratorGenerateSecure(count)
	}
	public generateMaximum(count: number = 1): ApiKeyGenerateResult {
		return apiKeyGeneratorGenerateMaximum(count)
	}
	public export(result: ApiKeyGenerateResult, exportFormat: ApiKeyExportFormat = 'json'): string {
		return apiKeyGeneratorExportTokens(result, exportFormat)
	}
	public exportToEnv(result: ApiKeyGenerateResult, prefix: string = 'API_KEY'): string {
		return apiKeyGeneratorExportToEnv(result, prefix)
	}
	public validate(key: string, options?: ApiKeyValidationOptions): ApiKeyValidationResult {
		return apiKeyGeneratorValidate(key, options)
	}
	public isStrong(key: string, minEntropy?: number): boolean {
		return apiKeyGeneratorIsStrong(key, minEntropy)
	}
	public isProductionReady(key: string): boolean {
		return apiKeyGeneratorIsProductionReady(key)
	}
	public getEntropyBits(): number {
		return this.entropyBits
	}
	public getStrength(): ApiKeyStrength {
		return this.strength
	}
	public getSecurityLevel(): ApiKeySecurityLevel {
		return this.securityLevel
	}
	public getOptions(): Readonly<
		Required<Omit<ApiKeyGenerateOptions, 'prefix'>> & { prefix?: string }
	> {
		return Object.freeze({ ...this.options })
	}
	public static resetRateLimit(): void {
		ApiKeyGenerator.requestCount = 0
		ApiKeyGenerator.lastRequestTime = 0
	}
}
export function apiKeyGeneratorDebugInfo(): {
	readonly version: string
	readonly supportedFormats: readonly ApiKeyFormat[]
	readonly supportedExportFormats: readonly ApiKeyExportFormat[]
	readonly constants: Record<string, unknown>
} {
	return {
		version: '1.0.0',
		supportedFormats: [...API_KEY_GENERATOR_SUPPORTED_FORMATS],
		supportedExportFormats: [...API_KEY_GENERATOR_EXPORT_FORMATS],
		constants: {
			MIN_COUNT: API_KEY_GENERATOR_MIN_COUNT,
			MAX_COUNT: API_KEY_GENERATOR_MAX_COUNT,
			MIN_LENGTH: API_KEY_GENERATOR_MIN_LENGTH,
			MAX_LENGTH: API_KEY_GENERATOR_MAX_LENGTH,
			SECURE_LENGTH: API_KEY_GENERATOR_SECURE_LENGTH,
			MAX_PREFIX_LENGTH: API_KEY_GENERATOR_MAX_PREFIX_LENGTH,
			MIN_ENTROPY_PRODUCTION: API_KEY_GENERATOR_MIN_ENTROPY_FOR_PRODUCTION,
			MIN_ENTROPY_SENSITIVE: API_KEY_GENERATOR_MIN_ENTROPY_FOR_SENSITIVE,
			RATE_LIMIT_WINDOW_MS: API_KEY_GENERATOR_RATE_LIMIT_WINDOW_MS,
			RATE_LIMIT_MAX_REQUESTS: API_KEY_GENERATOR_RATE_LIMIT_MAX_REQUESTS,
		},
	}
}
export function apiKeyGeneratorBenchmark(iterations: number = 100): {
	readonly avgTimeMs: number
	readonly totalTimeMs: number
	readonly iterations: number
	readonly keysPerSecond: number
} {
	const startTime = Date.now()
	for (let i = 0; i < iterations; i++) {
		apiKeyGeneratorGenerateTokens({ count: 1, length: 32, format: 'alphanumeric' })
	}
	const endTime = Date.now()
	const totalTimeMs = endTime - startTime
	const avgTimeMs = totalTimeMs / iterations
	const keysPerSecond = (iterations / totalTimeMs) * 1000
	return {
		avgTimeMs: Math.round(avgTimeMs * 100) / 100,
		totalTimeMs,
		iterations,
		keysPerSecond: Math.round(keysPerSecond * 100) / 100,
	}
}
export default {
	generate: apiKeyGeneratorGenerateTokens,
	generateOne: apiKeyGeneratorGenerateToken,
	generateString: apiKeyGeneratorGenerateKeyString,
	generateBasic: apiKeyGeneratorGenerateBasic,
	generateStandard: apiKeyGeneratorGenerateStandard,
	generateSecure: apiKeyGeneratorGenerateSecure,
	generateMaximum: apiKeyGeneratorGenerateMaximum,
	generateWithPreset: apiKeyGeneratorGenerateWithPreset,
	validate: apiKeyGeneratorValidate,
	isStrong: apiKeyGeneratorIsStrong,
	isProductionReady: apiKeyGeneratorIsProductionReady,
	export: apiKeyGeneratorExportTokens,
	exportToEnv: apiKeyGeneratorExportToEnv,
	getSecurityReport: apiKeyGeneratorGetSecurityReport,
	Generator: ApiKeyGenerator,
	presets: apiKeyGeneratorPresets,
	helpers: {
		detectFormat: apiKeyGeneratorDetectFormat,
		extractPrefix: apiKeyGeneratorExtractPrefix,
		calculateEntropy: apiKeyGeneratorCalculateEntropyBits,
		getStrength: apiKeyGeneratorGetStrength,
		getSecurityLevel: apiKeyGeneratorGetSecurityLevel,
		getLengthStrength: apiKeyGeneratorGetLengthStrength,
		compareLengths: apiKeyGeneratorCompareLengths,
		isLengthSecure: apiKeyGeneratorIsLengthSecure,
		getRecommendedLength: apiKeyGeneratorGetRecommendedLength,
	},
	debug: {
		info: apiKeyGeneratorDebugInfo,
		benchmark: apiKeyGeneratorBenchmark,
	},
	constants: {
		SUPPORTED_FORMATS: API_KEY_GENERATOR_SUPPORTED_FORMATS,
		EXPORT_FORMATS: API_KEY_GENERATOR_EXPORT_FORMATS,
		MIN_COUNT: API_KEY_GENERATOR_MIN_COUNT,
		MAX_COUNT: API_KEY_GENERATOR_MAX_COUNT,
		MIN_LENGTH: API_KEY_GENERATOR_MIN_LENGTH,
		MAX_LENGTH: API_KEY_GENERATOR_MAX_LENGTH,
		SECURE_LENGTH: API_KEY_GENERATOR_SECURE_LENGTH,
		MAX_PREFIX_LENGTH: API_KEY_GENERATOR_MAX_PREFIX_LENGTH,
		MIN_ENTROPY_PRODUCTION: API_KEY_GENERATOR_MIN_ENTROPY_FOR_PRODUCTION,
		MIN_ENTROPY_SENSITIVE: API_KEY_GENERATOR_MIN_ENTROPY_FOR_SENSITIVE,
		RATE_LIMIT_WINDOW_MS: API_KEY_GENERATOR_RATE_LIMIT_WINDOW_MS,
		RATE_LIMIT_MAX_REQUESTS: API_KEY_GENERATOR_RATE_LIMIT_MAX_REQUESTS,
		FORBIDDEN_PREFIXES: API_KEY_GENERATOR_FORBIDDEN_PREFIXES,
	},
}
