import { randomBytes } from 'crypto'
import { ValidationError } from '../../../error.js'
export const OAUTH_GENERATOR_SUPPORTED_TOKEN_TYPE_VALUES = Object.freeze([
	'Bearer',
	'MAC',
	'Basic',
] as const)
export const OAUTH_GENERATOR_AVAILABLE_TOKEN_ENCODING_FORMATS = Object.freeze([
	'base64',
	'base64url',
	'hex',
	'alphanumeric',
] as const)
export const OAUTH_GENERATOR_SUPPORTED_EXPORT_FORMATS = Object.freeze([
	'json',
	'txt',
	'csv',
] as const)
export const OAUTH_GENERATOR_GENERATION_MINIMUM_COUNT = 1
export const OAUTH_GENERATOR_GENERATION_MAXIMUM_COUNT = 10
export const OAUTH_GENERATOR_GENERATION_DEFAULT_COUNT = 1
export const OAUTH_GENERATOR_GENERATION_MINIMUM_TOKEN_LENGTH = 20
export const OAUTH_GENERATOR_GENERATION_MAXIMUM_TOKEN_LENGTH = 256
export const OAUTH_GENERATOR_GENERATION_DEFAULT_TOKEN_LENGTH = 40
export const OAUTH_GENERATOR_GENERATION_DEFAULT_EXPIRES_IN = 3600
export const OAUTH_GENERATOR_GENERATION_MINIMUM_EXPIRES_IN = 60
export const OAUTH_GENERATOR_GENERATION_MAXIMUM_EXPIRES_IN = 31536000
export const OAUTH_GENERATOR_BASE32_ENCODING_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
export const OAUTH_GENERATOR_ENTROPY_THRESHOLDS = Object.freeze([
	{ min: 0, max: 63, label: 'weak' as const },
	{ min: 64, max: 127, label: 'medium' as const },
	{ min: 128, max: 255, label: 'strong' as const },
	{ min: 256, max: Infinity, label: 'very_strong' as const },
] as const)
export type OAuthGeneratorTokenType = (typeof OAUTH_GENERATOR_SUPPORTED_TOKEN_TYPE_VALUES)[number]
export type OAuthGeneratorTokenFormat =
	(typeof OAUTH_GENERATOR_AVAILABLE_TOKEN_ENCODING_FORMATS)[number]
export type OAuthGeneratorExportFormat = (typeof OAUTH_GENERATOR_SUPPORTED_EXPORT_FORMATS)[number]
export type OAuthGeneratorStrength = 'weak' | 'medium' | 'strong' | 'very_strong'
export interface OAuthGeneratorTokenGenerationOptions {
	count?: number
	length?: number
	format?: OAuthGeneratorTokenFormat
	tokenType?: OAuthGeneratorTokenType
	expiresIn?: number
	includeRefreshToken?: boolean
	includeIdToken?: boolean
	includeTimestamp?: boolean
	includeEntropy?: boolean
	scope?: string
}
export interface OAuthGeneratorGeneratedTokenSet {
	readonly access_token: string
	readonly refresh_token?: string
	readonly id_token?: string
	readonly token_type: OAuthGeneratorTokenType
	readonly expires_in: number
	readonly scope?: string
	readonly timestamp?: number
	readonly entropyBits?: number
}
export interface OAuthGeneratorGenerateMetadata {
	readonly count: number
	readonly length: number
	readonly format: OAuthGeneratorTokenFormat
	readonly tokenType: OAuthGeneratorTokenType
	readonly expiresIn: number
	readonly includeRefreshToken: boolean
	readonly includeIdToken: boolean
	readonly includeTimestamp: boolean
	readonly includeEntropy: boolean
	readonly scope?: string
	readonly poolSize: number
	readonly avgEntropyBits: number
	readonly strength: OAuthGeneratorStrength
}
export interface OAuthGeneratorTokenGenerationResult {
	readonly tokens: readonly OAuthGeneratorGeneratedTokenSet[]
	readonly metadata: OAuthGeneratorGenerateMetadata
}
export interface OAuthGeneratorValidationResult {
	readonly isValid: boolean
	readonly isExpired: boolean
	readonly strength: OAuthGeneratorStrength
	readonly entropyBits: number
	readonly tokenType: OAuthGeneratorTokenType | 'unknown'
	readonly hasRefreshToken: boolean
	readonly hasIdToken: boolean
	readonly expiresAt?: number
	readonly errors: readonly string[]
	readonly warnings: readonly string[]
}
function oauthGeneratorEncodeBufferToBase32Alphabet(oauthGeneratorBuffer: Buffer): string {
	let bits = 0
	let value = 0
	let output = ''
	for (let i = 0; i < oauthGeneratorBuffer.length; i++) {
		const byte = oauthGeneratorBuffer[i]!
		value = (value << 8) | byte
		bits += 8
		while (bits >= 5) {
			const index = (value >>> (bits - 5)) & 31
			output += OAUTH_GENERATOR_BASE32_ENCODING_ALPHABET[index]!
			bits -= 5
		}
	}
	if (bits > 0) {
		const index = (value << (5 - bits)) & 31
		output += OAUTH_GENERATOR_BASE32_ENCODING_ALPHABET[index]!
	}
	return output
}
const oauthGeneratorFormatToEncoderFunctionMap: Record<
	OAuthGeneratorTokenFormat,
	(buf: Buffer) => string
> = {
	base64: (oauthGeneratorBuffer) => oauthGeneratorBuffer.toString('base64').replace(/=+$/, ''),
	base64url: (oauthGeneratorBuffer) => oauthGeneratorBuffer.toString('base64url'),
	hex: (oauthGeneratorBuffer) => oauthGeneratorBuffer.toString('hex'),
	alphanumeric: oauthGeneratorEncodeBufferToBase32Alphabet,
}
function oauthGeneratorValidateOptions(
	oauthGeneratorOptions: OAuthGeneratorTokenGenerationOptions,
): Required<Omit<OAuthGeneratorTokenGenerationOptions, 'scope'>> & { scope?: string } {
	const oauthGeneratorCount =
		oauthGeneratorOptions.count ?? OAUTH_GENERATOR_GENERATION_DEFAULT_COUNT
	if (
		!Number.isInteger(oauthGeneratorCount) ||
		oauthGeneratorCount < OAUTH_GENERATOR_GENERATION_MINIMUM_COUNT ||
		oauthGeneratorCount > OAUTH_GENERATOR_GENERATION_MAXIMUM_COUNT
	) {
		throw new ValidationError(
			`count must be an integer between ${OAUTH_GENERATOR_GENERATION_MINIMUM_COUNT} and ${OAUTH_GENERATOR_GENERATION_MAXIMUM_COUNT}`,
			{ count: oauthGeneratorCount },
		)
	}
	const oauthGeneratorLength =
		oauthGeneratorOptions.length ?? OAUTH_GENERATOR_GENERATION_DEFAULT_TOKEN_LENGTH
	if (
		!Number.isInteger(oauthGeneratorLength) ||
		oauthGeneratorLength < OAUTH_GENERATOR_GENERATION_MINIMUM_TOKEN_LENGTH ||
		oauthGeneratorLength > OAUTH_GENERATOR_GENERATION_MAXIMUM_TOKEN_LENGTH
	) {
		throw new ValidationError(
			`length must be an integer between ${OAUTH_GENERATOR_GENERATION_MINIMUM_TOKEN_LENGTH} and ${OAUTH_GENERATOR_GENERATION_MAXIMUM_TOKEN_LENGTH}`,
			{ length: oauthGeneratorLength },
		)
	}
	const oauthGeneratorFormat = oauthGeneratorOptions.format ?? 'base64url'
	if (
		!OAUTH_GENERATOR_AVAILABLE_TOKEN_ENCODING_FORMATS.includes(
			oauthGeneratorFormat as OAuthGeneratorTokenFormat,
		)
	) {
		throw new ValidationError(
			`format must be one of: ${OAUTH_GENERATOR_AVAILABLE_TOKEN_ENCODING_FORMATS.join(', ')}`,
			{ format: oauthGeneratorFormat },
		)
	}
	const oauthGeneratorTokenType = oauthGeneratorOptions.tokenType ?? 'Bearer'
	if (
		!OAUTH_GENERATOR_SUPPORTED_TOKEN_TYPE_VALUES.includes(
			oauthGeneratorTokenType as OAuthGeneratorTokenType,
		)
	) {
		throw new ValidationError(
			`tokenType must be one of: ${OAUTH_GENERATOR_SUPPORTED_TOKEN_TYPE_VALUES.join(', ')}`,
			{ tokenType: oauthGeneratorTokenType },
		)
	}
	const oauthGeneratorExpiresIn =
		oauthGeneratorOptions.expiresIn ?? OAUTH_GENERATOR_GENERATION_DEFAULT_EXPIRES_IN
	if (
		!Number.isInteger(oauthGeneratorExpiresIn) ||
		oauthGeneratorExpiresIn < OAUTH_GENERATOR_GENERATION_MINIMUM_EXPIRES_IN ||
		oauthGeneratorExpiresIn > OAUTH_GENERATOR_GENERATION_MAXIMUM_EXPIRES_IN
	) {
		throw new ValidationError(
			`expiresIn must be an integer between ${OAUTH_GENERATOR_GENERATION_MINIMUM_EXPIRES_IN} and ${OAUTH_GENERATOR_GENERATION_MAXIMUM_EXPIRES_IN}`,
			{ expiresIn: oauthGeneratorExpiresIn },
		)
	}
	const includeRefreshToken = oauthGeneratorOptions.includeRefreshToken ?? false
	const includeIdToken = oauthGeneratorOptions.includeIdToken ?? false
	const includeTimestamp = oauthGeneratorOptions.includeTimestamp ?? false
	const includeEntropy = oauthGeneratorOptions.includeEntropy ?? false
	if (typeof includeRefreshToken !== 'boolean') {
		throw new ValidationError('includeRefreshToken must be a boolean', { includeRefreshToken })
	}
	if (typeof includeIdToken !== 'boolean') {
		throw new ValidationError('includeIdToken must be a boolean', { includeIdToken })
	}
	if (typeof includeTimestamp !== 'boolean') {
		throw new ValidationError('includeTimestamp must be a boolean', { includeTimestamp })
	}
	if (typeof includeEntropy !== 'boolean') {
		throw new ValidationError('includeEntropy must be a boolean', { includeEntropy })
	}
	let scope: string | undefined
	if (oauthGeneratorOptions.scope !== undefined) {
		if (typeof oauthGeneratorOptions.scope !== 'string') {
			throw new ValidationError('scope must be a string', {
				scope: oauthGeneratorOptions.scope,
			})
		}
		if (oauthGeneratorOptions.scope.length > 200) {
			throw new ValidationError('scope length must not exceed 200 characters', {
				scopeLength: oauthGeneratorOptions.scope.length,
			})
		}
		scope = oauthGeneratorOptions.scope
	}
	return {
		count: oauthGeneratorCount,
		length: oauthGeneratorLength,
		format: oauthGeneratorFormat as OAuthGeneratorTokenFormat,
		tokenType: oauthGeneratorTokenType as OAuthGeneratorTokenType,
		expiresIn: oauthGeneratorExpiresIn,
		includeRefreshToken,
		includeIdToken,
		includeTimestamp,
		includeEntropy,
		...(scope !== undefined && { scope }),
	}
}
function oauthGeneratorGenerateSingleTokenString(
	oauthGeneratorLength: number,
	oauthGeneratorFormat: OAuthGeneratorTokenFormat,
): string {
	const oauthGeneratorBytes = randomBytes(oauthGeneratorLength)
	return oauthGeneratorFormatToEncoderFunctionMap[oauthGeneratorFormat](oauthGeneratorBytes)
}
function oauthGeneratorCalculateEntropy(byteLength: number): number {
	if (byteLength <= 0) return 0
	const entropy = byteLength * 8
	return Math.round(entropy * 10) / 10
}
function oauthGeneratorGetStrength(entropyBits: number): OAuthGeneratorStrength {
	const threshold = OAUTH_GENERATOR_ENTROPY_THRESHOLDS.find(
		(t) => entropyBits >= t.min && entropyBits <= t.max,
	)
	return threshold?.label ?? 'weak'
}
function oauthGeneratorGetPoolSize(format: OAuthGeneratorTokenFormat): number {
	switch (format) {
		case 'base64':
		case 'base64url':
			return 64
		case 'hex':
			return 16
		case 'alphanumeric':
			return 32
		default:
			return 64
	}
}
function oauthGeneratorGenerateCompleteTokenSet(
	validated: Required<Omit<OAuthGeneratorTokenGenerationOptions, 'scope'>> & { scope?: string },
): OAuthGeneratorGeneratedTokenSet {
	const accessToken = oauthGeneratorGenerateSingleTokenString(validated.length, validated.format)
	const timestamp = Math.floor(Date.now() / 1000)
	const entropyBits = oauthGeneratorCalculateEntropy(validated.length)
	return {
		access_token: accessToken,
		token_type: validated.tokenType,
		expires_in: validated.expiresIn,
		...(validated.scope && { scope: validated.scope }),
		...(validated.includeRefreshToken && {
			refresh_token: oauthGeneratorGenerateSingleTokenString(
				validated.length,
				validated.format,
			),
		}),
		...(validated.includeIdToken && {
			id_token: oauthGeneratorGenerateSingleTokenString(validated.length, validated.format),
		}),
		...(validated.includeTimestamp && { timestamp }),
		...(validated.includeEntropy && { entropyBits }),
	}
}
function oauthGeneratorBuildMetadata(
	validated: Required<Omit<OAuthGeneratorTokenGenerationOptions, 'scope'>> & { scope?: string },
	avgEntropyBits: number,
): OAuthGeneratorGenerateMetadata {
	const poolSize = oauthGeneratorGetPoolSize(validated.format)
	const strength = oauthGeneratorGetStrength(avgEntropyBits)
	const base: OAuthGeneratorGenerateMetadata = {
		count: validated.count,
		length: validated.length,
		format: validated.format,
		tokenType: validated.tokenType,
		expiresIn: validated.expiresIn,
		includeRefreshToken: validated.includeRefreshToken,
		includeIdToken: validated.includeIdToken,
		includeTimestamp: validated.includeTimestamp,
		includeEntropy: validated.includeEntropy,
		poolSize,
		avgEntropyBits,
		strength,
	}
	if (validated.scope) {
		return { ...base, scope: validated.scope }
	}
	return base
}
export function oauthGeneratorGenerateTokens(
	oauthGeneratorOptions: OAuthGeneratorTokenGenerationOptions = {},
): OAuthGeneratorTokenGenerationResult {
	const validated = oauthGeneratorValidateOptions(oauthGeneratorOptions)
	const tokens: OAuthGeneratorGeneratedTokenSet[] = []
	let totalEntropy = 0
	for (let i = 0; i < validated.count; i++) {
		const tokenSet = oauthGeneratorGenerateCompleteTokenSet(validated)
		tokens.push(tokenSet)
		if (validated.includeEntropy && tokenSet.entropyBits !== undefined) {
			totalEntropy += tokenSet.entropyBits
		}
	}
	const avgEntropyBits = validated.includeEntropy
		? Math.round((totalEntropy / validated.count) * 10) / 10
		: oauthGeneratorCalculateEntropy(validated.length)
	const metadata = oauthGeneratorBuildMetadata(validated, avgEntropyBits)
	return {
		tokens: Object.freeze(tokens) as readonly OAuthGeneratorGeneratedTokenSet[],
		metadata: Object.freeze(metadata),
	}
}
export function oauthGeneratorGenerateToken(
	oauthGeneratorOptions: OAuthGeneratorTokenGenerationOptions = {},
): OAuthGeneratorGeneratedTokenSet {
	const result = oauthGeneratorGenerateTokens({ ...oauthGeneratorOptions, count: 1 })
	return result.tokens[0]!
}
export function oauthGeneratorGenerateSample(): OAuthGeneratorGeneratedTokenSet {
	return oauthGeneratorGenerateTokens({
		count: 1,
		length: 40,
		format: 'base64url',
		tokenType: 'Bearer',
		expiresIn: 3600,
		includeRefreshToken: true,
		includeIdToken: true,
	}).tokens[0]!
}
export function oauthGeneratorGenerateStrong(
	oauthGeneratorOptions: Partial<OAuthGeneratorTokenGenerationOptions> = {},
): OAuthGeneratorGeneratedTokenSet {
	return oauthGeneratorGenerateTokens({
		count: 1,
		length: oauthGeneratorOptions.length ?? 64,
		format: oauthGeneratorOptions.format ?? 'base64url',
		tokenType: 'Bearer',
		expiresIn: oauthGeneratorOptions.expiresIn ?? 7200,
		includeRefreshToken: true,
		includeIdToken: true,
		includeTimestamp: true,
		includeEntropy: true,
		...oauthGeneratorOptions,
	}).tokens[0]!
}
export function oauthGeneratorValidate(
	tokenSet: OAuthGeneratorGeneratedTokenSet,
): OAuthGeneratorValidationResult {
	const errors: string[] = []
	const warnings: string[] = []
	if (!tokenSet.access_token || typeof tokenSet.access_token !== 'string') {
		return {
			isValid: false,
			isExpired: false,
			strength: 'weak' as const,
			entropyBits: 0,
			tokenType: 'unknown' as const,
			hasRefreshToken: false,
			hasIdToken: false,
			errors: ['access_token is missing or invalid'],
			warnings: [],
		}
	}
	const accessTokenLength = tokenSet.access_token.length
	if (accessTokenLength < 20) {
		errors.push('access_token is too short (minimum 20 characters)')
	}
	if (accessTokenLength < 40) {
		warnings.push('access_token length is below recommended (40 characters)')
	}
	let tokenType: OAuthGeneratorTokenType | 'unknown' = 'unknown'
	if (
		OAUTH_GENERATOR_SUPPORTED_TOKEN_TYPE_VALUES.includes(
			tokenSet.token_type as OAuthGeneratorTokenType,
		)
	) {
		tokenType = tokenSet.token_type as OAuthGeneratorTokenType
	} else {
		warnings.push('Unknown token_type value')
	}
	const estimatedEntropy = accessTokenLength * 6
	const strength = oauthGeneratorGetStrength(estimatedEntropy)
	if (strength === 'weak') {
		errors.push('Token strength is too weak')
	} else if (strength === 'medium') {
		warnings.push('Token strength could be improved')
	}
	if (tokenSet.expires_in && tokenSet.expires_in <= 0) {
		warnings.push('expires_in should be a positive value')
	}
	const hasRefreshToken = tokenSet.refresh_token !== undefined
	const hasIdToken = tokenSet.id_token !== undefined
	if (!hasRefreshToken) {
		warnings.push('No refresh_token included - consider adding for better UX')
	}
	return {
		isValid: errors.length === 0,
		isExpired: false,
		strength,
		entropyBits: estimatedEntropy,
		tokenType,
		hasRefreshToken,
		hasIdToken,
		errors: Object.freeze(errors),
		warnings: Object.freeze(warnings),
	}
}
export function oauthGeneratorIsStrong(
	tokenSet: OAuthGeneratorGeneratedTokenSet,
	minEntropy: number = 128,
): boolean {
	const validation = oauthGeneratorValidate(tokenSet)
	return validation.isValid && validation.entropyBits >= minEntropy
}
export function oauthGeneratorCalculateTokenEntropy(token: string): number {
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
export function oauthGeneratorExportTokens(
	oauthGeneratorResult: OAuthGeneratorTokenGenerationResult,
	oauthGeneratorExportFormat: OAuthGeneratorExportFormat = 'json',
): string {
	const { tokens: oauthGeneratorTokens, metadata: oauthGeneratorMetadata } = oauthGeneratorResult
	switch (oauthGeneratorExportFormat) {
		case 'json':
			return JSON.stringify(
				{ metadata: oauthGeneratorMetadata, tokens: oauthGeneratorTokens },
				null,
				2,
			)
		case 'txt':
			return oauthGeneratorTokens
				.map((oauthGeneratorSingleTokenSet) => {
					const oauthGeneratorLines = [
						`access_token: ${oauthGeneratorSingleTokenSet.access_token}`,
						`token_type: ${oauthGeneratorSingleTokenSet.token_type}`,
						`expires_in: ${oauthGeneratorSingleTokenSet.expires_in}`,
					]
					if (oauthGeneratorSingleTokenSet.scope)
						oauthGeneratorLines.push(`scope: ${oauthGeneratorSingleTokenSet.scope}`)
					if (oauthGeneratorSingleTokenSet.refresh_token)
						oauthGeneratorLines.push(
							`refresh_token: ${oauthGeneratorSingleTokenSet.refresh_token}`,
						)
					if (oauthGeneratorSingleTokenSet.id_token)
						oauthGeneratorLines.push(
							`id_token: ${oauthGeneratorSingleTokenSet.id_token}`,
						)
					if (oauthGeneratorSingleTokenSet.timestamp)
						oauthGeneratorLines.push(
							`timestamp: ${oauthGeneratorSingleTokenSet.timestamp}`,
						)
					if (oauthGeneratorSingleTokenSet.entropyBits)
						oauthGeneratorLines.push(
							`entropyBits: ${oauthGeneratorSingleTokenSet.entropyBits}`,
						)
					return oauthGeneratorLines.join('\n')
				})
				.join('\n\n')
		case 'csv': {
			const oauthGeneratorHasRefresh = oauthGeneratorTokens.some(
				(oauthGeneratorSingleTokenSet) => oauthGeneratorSingleTokenSet.refresh_token,
			)
			const oauthGeneratorHasId = oauthGeneratorTokens.some(
				(oauthGeneratorSingleTokenSet) => oauthGeneratorSingleTokenSet.id_token,
			)
			const oauthGeneratorHasScope = oauthGeneratorTokens.some(
				(oauthGeneratorSingleTokenSet) => oauthGeneratorSingleTokenSet.scope,
			)
			const oauthGeneratorHasTimestamp = oauthGeneratorTokens.some(
				(oauthGeneratorSingleTokenSet) => oauthGeneratorSingleTokenSet.timestamp,
			)
			const oauthGeneratorHasEntropy = oauthGeneratorTokens.some(
				(oauthGeneratorSingleTokenSet) => oauthGeneratorSingleTokenSet.entropyBits,
			)
			const oauthGeneratorHeaders = ['access_token', 'token_type', 'expires_in']
			if (oauthGeneratorHasScope) oauthGeneratorHeaders.push('scope')
			if (oauthGeneratorHasRefresh) oauthGeneratorHeaders.push('refresh_token')
			if (oauthGeneratorHasId) oauthGeneratorHeaders.push('id_token')
			if (oauthGeneratorHasTimestamp) oauthGeneratorHeaders.push('timestamp')
			if (oauthGeneratorHasEntropy) oauthGeneratorHeaders.push('entropyBits')
			const oauthGeneratorEscapeCsv = (oauthGeneratorValue: string | number): string => {
				const oauthGeneratorString = String(oauthGeneratorValue)
				if (
					oauthGeneratorString.includes('"') ||
					oauthGeneratorString.includes(',') ||
					oauthGeneratorString.includes('\n')
				) {
					return `"${oauthGeneratorString.replace(/"/g, '""')}"`
				}
				return oauthGeneratorString
			}
			const oauthGeneratorRows = oauthGeneratorTokens.map((oauthGeneratorSingleTokenSet) => {
				const oauthGeneratorCols = [
					oauthGeneratorEscapeCsv(oauthGeneratorSingleTokenSet.access_token),
					oauthGeneratorSingleTokenSet.token_type,
					oauthGeneratorSingleTokenSet.expires_in.toString(),
				]
				if (oauthGeneratorHasScope && oauthGeneratorSingleTokenSet.scope)
					oauthGeneratorCols.push(
						oauthGeneratorEscapeCsv(oauthGeneratorSingleTokenSet.scope),
					)
				if (oauthGeneratorHasRefresh)
					oauthGeneratorCols.push(
						oauthGeneratorSingleTokenSet.refresh_token
							? oauthGeneratorEscapeCsv(oauthGeneratorSingleTokenSet.refresh_token)
							: '',
					)
				if (oauthGeneratorHasId)
					oauthGeneratorCols.push(
						oauthGeneratorSingleTokenSet.id_token
							? oauthGeneratorEscapeCsv(oauthGeneratorSingleTokenSet.id_token)
							: '',
					)
				if (oauthGeneratorHasTimestamp && oauthGeneratorSingleTokenSet.timestamp)
					oauthGeneratorCols.push(oauthGeneratorSingleTokenSet.timestamp.toString())
				if (oauthGeneratorHasEntropy && oauthGeneratorSingleTokenSet.entropyBits)
					oauthGeneratorCols.push(oauthGeneratorSingleTokenSet.entropyBits.toString())
				return oauthGeneratorCols.join(',')
			})
			return oauthGeneratorHeaders.join(',') + '\n' + oauthGeneratorRows.join('\n')
		}
		default:
			throw new ValidationError(`Unsupported export format: ${oauthGeneratorExportFormat}`, {
				format: oauthGeneratorExportFormat,
			})
	}
}
export function oauthGeneratorExportToEnv(
	oauthGeneratorResult: OAuthGeneratorTokenGenerationResult,
	prefix: string = 'OAUTH_GENERATOR',
): string {
	const { tokens } = oauthGeneratorResult
	return tokens
		.map((t, i) => {
			const lines = [`${prefix}_${i + 1}_ACCESS_TOKEN="${t.access_token}"`]
			if (t.refresh_token) lines.push(`${prefix}_${i + 1}_REFRESH_TOKEN="${t.refresh_token}"`)
			if (t.id_token) lines.push(`${prefix}_${i + 1}_ID_TOKEN="${t.id_token}"`)
			lines.push(`${prefix}_${i + 1}_TOKEN_TYPE="${t.token_type}"`)
			lines.push(`${prefix}_${i + 1}_EXPIRES_IN=${t.expires_in}`)
			return lines.join('\n')
		})
		.join('\n\n')
}
export class OAuthGeneratorGenerator {
	private readonly options: Required<Omit<OAuthGeneratorTokenGenerationOptions, 'scope'>> & {
		scope?: string
	}
	private readonly entropyBits: number
	private readonly strength: OAuthGeneratorStrength
	constructor(oauthGeneratorOptions: OAuthGeneratorTokenGenerationOptions = {}) {
		this.options = oauthGeneratorValidateOptions(oauthGeneratorOptions)
		this.entropyBits = oauthGeneratorCalculateEntropy(this.options.length)
		this.strength = oauthGeneratorGetStrength(this.entropyBits)
	}
	public generate(): OAuthGeneratorTokenGenerationResult {
		const tokens: OAuthGeneratorGeneratedTokenSet[] = []
		let totalEntropy = 0
		for (let i = 0; i < this.options.count; i++) {
			const tokenSet = oauthGeneratorGenerateCompleteTokenSet(this.options)
			tokens.push(tokenSet)
			if (this.options.includeEntropy && tokenSet.entropyBits !== undefined) {
				totalEntropy += tokenSet.entropyBits
			}
		}
		const avgEntropyBits = this.options.includeEntropy
			? Math.round((totalEntropy / this.options.count) * 10) / 10
			: this.entropyBits
		const metadata = oauthGeneratorBuildMetadata(this.options, avgEntropyBits)
		return {
			tokens: Object.freeze(tokens) as readonly OAuthGeneratorGeneratedTokenSet[],
			metadata: Object.freeze(metadata),
		}
	}
	public generateOne(): OAuthGeneratorGeneratedTokenSet {
		const result = this.generate()
		return result.tokens[0]!
	}
	public generateStrong(): OAuthGeneratorGeneratedTokenSet {
		return oauthGeneratorGenerateStrong({
			length: Math.max(this.options.length, 64),
			format: this.options.format,
			tokenType: this.options.tokenType,
		})
	}
	public export(
		result: OAuthGeneratorTokenGenerationResult,
		format: OAuthGeneratorExportFormat = 'json',
	): string {
		return oauthGeneratorExportTokens(result, format)
	}
	public exportToEnv(
		result: OAuthGeneratorTokenGenerationResult,
		prefix: string = 'OAUTH_GENERATOR',
	): string {
		return oauthGeneratorExportToEnv(result, prefix)
	}
	public validate(tokenSet: OAuthGeneratorGeneratedTokenSet): OAuthGeneratorValidationResult {
		return oauthGeneratorValidate(tokenSet)
	}
	public isStrong(tokenSet: OAuthGeneratorGeneratedTokenSet, minEntropy: number = 128): boolean {
		return oauthGeneratorIsStrong(tokenSet, minEntropy)
	}
	public getEntropyBits(): number {
		return this.entropyBits
	}
	public getStrength(): OAuthGeneratorStrength {
		return this.strength
	}
	public getOptions(): Readonly<
		Required<Omit<OAuthGeneratorTokenGenerationOptions, 'scope'>> & {
			scope?: string
		}
	> {
		return Object.freeze({ ...this.options })
	}
}
export const oauthGeneratorPresets = Object.freeze({
	basic: {
		length: 40,
		format: 'base64url' as const,
		tokenType: 'Bearer' as const,
		expiresIn: 3600,
		includeRefreshToken: false,
		includeIdToken: false,
		includeTimestamp: false,
		includeEntropy: false,
	} as OAuthGeneratorTokenGenerationOptions,
	standard: {
		length: 40,
		format: 'base64url' as const,
		tokenType: 'Bearer' as const,
		expiresIn: 3600,
		includeRefreshToken: true,
		includeIdToken: false,
		includeTimestamp: true,
		includeEntropy: true,
	} as OAuthGeneratorTokenGenerationOptions,
	strong: {
		length: 64,
		format: 'base64url' as const,
		tokenType: 'Bearer' as const,
		expiresIn: 7200,
		includeRefreshToken: true,
		includeIdToken: true,
		includeTimestamp: true,
		includeEntropy: true,
	} as OAuthGeneratorTokenGenerationOptions,
	maximum: {
		length: 128,
		format: 'hex' as const,
		tokenType: 'Bearer' as const,
		expiresIn: 3600,
		includeRefreshToken: true,
		includeIdToken: true,
		includeTimestamp: true,
		includeEntropy: true,
	} as OAuthGeneratorTokenGenerationOptions,
	shortLived: {
		length: 40,
		format: 'base64url' as const,
		tokenType: 'Bearer' as const,
		expiresIn: 1800,
		includeRefreshToken: true,
		includeIdToken: false,
		includeTimestamp: true,
		includeEntropy: false,
	} as OAuthGeneratorTokenGenerationOptions,
	refresh: {
		length: 64,
		format: 'base64url' as const,
		tokenType: 'Bearer' as const,
		expiresIn: 604800,
		includeRefreshToken: false,
		includeIdToken: false,
		includeTimestamp: true,
		includeEntropy: true,
	} as OAuthGeneratorTokenGenerationOptions,
	oidc: {
		length: 64,
		format: 'base64url' as const,
		tokenType: 'Bearer' as const,
		expiresIn: 3600,
		includeRefreshToken: true,
		includeIdToken: true,
		includeTimestamp: true,
		includeEntropy: true,
		scope: 'openid profile email',
	} as OAuthGeneratorTokenGenerationOptions,
} as const)
export type OAuthGeneratorPreset = keyof typeof oauthGeneratorPresets
export function oauthGeneratorGenerateWithPreset(
	preset: OAuthGeneratorPreset,
	overrides: Partial<OAuthGeneratorTokenGenerationOptions> = {},
): OAuthGeneratorTokenGenerationResult {
	const baseOptions = oauthGeneratorPresets[preset]
	return oauthGeneratorGenerateTokens({ ...baseOptions, ...overrides })
}
export function oauthGeneratorGetFormatStrength(
	format: OAuthGeneratorTokenFormat,
): OAuthGeneratorStrength {
	const poolSize = oauthGeneratorGetPoolSize(format)
	const entropyBits = Math.log2(poolSize) * 40
	return oauthGeneratorGetStrength(entropyBits)
}
export function oauthGeneratorCompareFormats(
	fmt1: OAuthGeneratorTokenFormat,
	fmt2: OAuthGeneratorTokenFormat,
): number {
	const strength1 = oauthGeneratorGetFormatStrength(fmt1)
	const strength2 = oauthGeneratorGetFormatStrength(fmt2)
	const strengthOrder: Record<OAuthGeneratorStrength, number> = {
		weak: 0,
		medium: 1,
		strong: 2,
		very_strong: 3,
	}
	return strengthOrder[strength2] - strengthOrder[strength1]
}
export function oauthGeneratorIsFormatSecure(
	format: OAuthGeneratorTokenFormat,
	minStrength: OAuthGeneratorStrength = 'strong',
): boolean {
	const strength = oauthGeneratorGetFormatStrength(format)
	const strengthOrder: Record<OAuthGeneratorStrength, number> = {
		weak: 0,
		medium: 1,
		strong: 2,
		very_strong: 3,
	}
	return strengthOrder[strength] >= strengthOrder[minStrength]
}
