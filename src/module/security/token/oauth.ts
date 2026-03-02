import { randomBytes } from 'crypto'
import { ValidationError } from '../../../error.js'
export const OAUTH_SUPPORTED_TOKEN_TYPE_VALUES = ['Bearer', 'MAC', 'Basic'] as const
export const OAUTH_AVAILABLE_TOKEN_ENCODING_FORMATS = [
	'base64',
	'base64url',
	'hex',
	'alphanumeric',
] as const
export type OAuthSupportedTokenTypeValue = (typeof OAUTH_SUPPORTED_TOKEN_TYPE_VALUES)[number]
export type OAuthAvailableTokenEncodingFormat =
	(typeof OAUTH_AVAILABLE_TOKEN_ENCODING_FORMATS)[number]
export interface OAuthTokenGenerationOptions {
	count?: number
	length?: number
	format?: OAuthAvailableTokenEncodingFormat
	tokenType?: OAuthSupportedTokenTypeValue
	expiresIn?: number
	includeRefreshToken?: boolean
	includeIdToken?: boolean
}
export interface OAuthGeneratedTokenSet {
	access_token: string
	refresh_token?: string
	id_token?: string
	token_type: OAuthSupportedTokenTypeValue
	expires_in: number
}
export interface OAuthTokenGenerationResult {
	tokens: OAuthGeneratedTokenSet[]
	metadata: {
		count: number
		length: number
		format: OAuthAvailableTokenEncodingFormat
		tokenType: OAuthSupportedTokenTypeValue
		expiresIn: number
		includeRefreshToken: boolean
		includeIdToken: boolean
	}
}
const OAUTH_GENERATION_MINIMUM_COUNT = 1
const OAUTH_GENERATION_MAXIMUM_COUNT = 10
const OAUTH_GENERATION_MINIMUM_TOKEN_LENGTH = 20
const OAUTH_GENERATION_MAXIMUM_TOKEN_LENGTH = 256
const OAUTH_BASE32_ENCODING_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
function oauthEncodeBufferToBase32Alphabet(oauthBuffer: Buffer): string {
	let bits = 0
	let value = 0
	let output = ''
	for (let i = 0; i < oauthBuffer.length; i++) {
		const byte = oauthBuffer[i]!
		value = (value << 8) | byte
		bits += 8
		while (bits >= 5) {
			const index = (value >>> (bits - 5)) & 31
			output += OAUTH_BASE32_ENCODING_ALPHABET[index]
			bits -= 5
		}
	}
	if (bits > 0) {
		const index = (value << (5 - bits)) & 31
		output += OAUTH_BASE32_ENCODING_ALPHABET[index]
	}
	return output
}
const oauthFormatToEncoderFunctionMap: Record<
	OAuthAvailableTokenEncodingFormat,
	(buf: Buffer) => string
> = {
	base64: (oauthBuffer) => oauthBuffer.toString('base64').replace(/=+$/, ''),
	base64url: (oauthBuffer) => oauthBuffer.toString('base64url'),
	hex: (oauthBuffer) => oauthBuffer.toString('hex'),
	alphanumeric: oauthEncodeBufferToBase32Alphabet,
}
function oauthValidateAndNormalizeGenerationOptions(
	oauthOptions: OAuthTokenGenerationOptions,
): Required<OAuthTokenGenerationOptions> {
	const oauthCount = oauthOptions.count ?? 1
	if (
		!Number.isInteger(oauthCount) ||
		oauthCount < OAUTH_GENERATION_MINIMUM_COUNT ||
		oauthCount > OAUTH_GENERATION_MAXIMUM_COUNT
	) {
		throw new ValidationError(
			`count must be an integer between ${OAUTH_GENERATION_MINIMUM_COUNT} and ${OAUTH_GENERATION_MAXIMUM_COUNT}`,
			{ count: oauthCount },
		)
	}
	const oauthLength = oauthOptions.length ?? 40
	if (
		!Number.isInteger(oauthLength) ||
		oauthLength < OAUTH_GENERATION_MINIMUM_TOKEN_LENGTH ||
		oauthLength > OAUTH_GENERATION_MAXIMUM_TOKEN_LENGTH
	) {
		throw new ValidationError(
			`length must be an integer between ${OAUTH_GENERATION_MINIMUM_TOKEN_LENGTH} and ${OAUTH_GENERATION_MAXIMUM_TOKEN_LENGTH}`,
			{ length: oauthLength },
		)
	}
	const oauthFormat = oauthOptions.format ?? 'base64url'
	if (!OAUTH_AVAILABLE_TOKEN_ENCODING_FORMATS.includes(oauthFormat)) {
		throw new ValidationError(
			`format must be one of: ${OAUTH_AVAILABLE_TOKEN_ENCODING_FORMATS.join(', ')}`,
			{ format: oauthFormat },
		)
	}
	const oauthTokenType = oauthOptions.tokenType ?? 'Bearer'
	if (!OAUTH_SUPPORTED_TOKEN_TYPE_VALUES.includes(oauthTokenType)) {
		throw new ValidationError(
			`tokenType must be one of: ${OAUTH_SUPPORTED_TOKEN_TYPE_VALUES.join(', ')}`,
			{
				tokenType: oauthTokenType,
			},
		)
	}
	const oauthExpiresIn = oauthOptions.expiresIn ?? 3600
	if (!Number.isInteger(oauthExpiresIn) || oauthExpiresIn <= 0) {
		throw new ValidationError('expiresIn must be a positive integer', {
			expiresIn: oauthExpiresIn,
		})
	}
	const oauthIncludeRefreshToken = oauthOptions.includeRefreshToken ?? false
	const oauthIncludeIdToken = oauthOptions.includeIdToken ?? false
	return {
		count: oauthCount,
		length: oauthLength,
		format: oauthFormat,
		tokenType: oauthTokenType,
		expiresIn: oauthExpiresIn,
		includeRefreshToken: oauthIncludeRefreshToken,
		includeIdToken: oauthIncludeIdToken,
	}
}
function oauthGenerateSingleTokenString(
	oauthLength: number,
	oauthFormat: OAuthAvailableTokenEncodingFormat,
): string {
	const oauthBytes = randomBytes(oauthLength)
	return oauthFormatToEncoderFunctionMap[oauthFormat](oauthBytes)
}
function oauthGenerateCompleteTokenSet(
	oauthLength: number,
	oauthFormat: OAuthAvailableTokenEncodingFormat,
	oauthTokenType: OAuthSupportedTokenTypeValue,
	oauthExpiresIn: number,
	oauthIncludeRefreshToken: boolean,
	oauthIncludeIdToken: boolean,
): OAuthGeneratedTokenSet {
	const oauthTokenSet: OAuthGeneratedTokenSet = {
		access_token: oauthGenerateSingleTokenString(oauthLength, oauthFormat),
		token_type: oauthTokenType,
		expires_in: oauthExpiresIn,
	}
	if (oauthIncludeRefreshToken) {
		oauthTokenSet.refresh_token = oauthGenerateSingleTokenString(oauthLength, oauthFormat)
	}
	if (oauthIncludeIdToken) {
		oauthTokenSet.id_token = oauthGenerateSingleTokenString(oauthLength, oauthFormat)
	}
	return oauthTokenSet
}
export function oauthGenerateTokens(
	oauthOptions: OAuthTokenGenerationOptions = {},
): OAuthTokenGenerationResult {
	const {
		count: oauthCount,
		length: oauthLength,
		format: oauthFormat,
		tokenType: oauthTokenType,
		expiresIn: oauthExpiresIn,
		includeRefreshToken: oauthIncludeRefreshToken,
		includeIdToken: oauthIncludeIdToken,
	} = oauthValidateAndNormalizeGenerationOptions(oauthOptions)
	const oauthTokens = Array.from({ length: oauthCount }, () =>
		oauthGenerateCompleteTokenSet(
			oauthLength,
			oauthFormat,
			oauthTokenType,
			oauthExpiresIn,
			oauthIncludeRefreshToken,
			oauthIncludeIdToken,
		),
	)
	return {
		tokens: oauthTokens,
		metadata: {
			count: oauthCount,
			length: oauthLength,
			format: oauthFormat,
			tokenType: oauthTokenType,
			expiresIn: oauthExpiresIn,
			includeRefreshToken: oauthIncludeRefreshToken,
			includeIdToken: oauthIncludeIdToken,
		},
	}
}
export function oauthExportTokens(
	oauthResult: OAuthTokenGenerationResult,
	oauthExportFormat: 'json' | 'txt' | 'csv' = 'json',
): string {
	const { tokens: oauthTokens, metadata: oauthMetadata } = oauthResult
	switch (oauthExportFormat) {
		case 'json':
			return JSON.stringify({ metadata: oauthMetadata, tokens: oauthTokens }, null, 2)
		case 'txt':
			return oauthTokens
				.map((oauthSingleTokenSet) => {
					const oauthLines = [
						`access_token: ${oauthSingleTokenSet.access_token}`,
						`token_type: ${oauthSingleTokenSet.token_type}`,
						`expires_in: ${oauthSingleTokenSet.expires_in}`,
					]
					if (oauthSingleTokenSet.refresh_token)
						oauthLines.push(`refresh_token: ${oauthSingleTokenSet.refresh_token}`)
					if (oauthSingleTokenSet.id_token)
						oauthLines.push(`id_token: ${oauthSingleTokenSet.id_token}`)
					return oauthLines.join('\n')
				})
				.join('\n\n')
		case 'csv': {
			const oauthHasRefresh = oauthTokens.some(
				(oauthSingleTokenSet) => oauthSingleTokenSet.refresh_token,
			)
			const oauthHasId = oauthTokens.some(
				(oauthSingleTokenSet) => oauthSingleTokenSet.id_token,
			)
			const oauthHeaders = ['access_token', 'token_type', 'expires_in']
			if (oauthHasRefresh) oauthHeaders.push('refresh_token')
			if (oauthHasId) oauthHeaders.push('id_token')
			const oauthEscapeCsv = (oauthValue: string) => {
				if (
					oauthValue.includes('"') ||
					oauthValue.includes(',') ||
					oauthValue.includes('\n')
				) {
					return `"${oauthValue.replace(/"/g, '""')}"`
				}
				return oauthValue
			}
			const oauthRows = oauthTokens.map((oauthSingleTokenSet) => {
				const oauthCols = [
					oauthEscapeCsv(oauthSingleTokenSet.access_token),
					oauthSingleTokenSet.token_type,
					oauthSingleTokenSet.expires_in.toString(),
				]
				if (oauthHasRefresh)
					oauthCols.push(
						oauthSingleTokenSet.refresh_token
							? oauthEscapeCsv(oauthSingleTokenSet.refresh_token)
							: '',
					)
				if (oauthHasId)
					oauthCols.push(
						oauthSingleTokenSet.id_token
							? oauthEscapeCsv(oauthSingleTokenSet.id_token)
							: '',
					)
				return oauthCols.join(',')
			})
			return oauthHeaders.join(',') + '\n' + oauthRows.join('\n')
		}
		default:
			throw new ValidationError(`Unsupported export format: ${oauthExportFormat}`)
	}
}
export function oauthGenerateSingleSampleTokenSet(): OAuthGeneratedTokenSet {
	const oauthSampleResult = oauthGenerateTokens({
		count: 1,
		length: 40,
		format: 'base64url',
		tokenType: 'Bearer',
		expiresIn: 3600,
		includeRefreshToken: true,
		includeIdToken: true,
	})
	return oauthSampleResult.tokens[0]!
}
