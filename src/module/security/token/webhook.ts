import { randomBytes, createHmac } from 'crypto'
import { ValidationError } from '../../../error.js'
export const WEBHOOK_SUPPORTED_HMAC_ALGORITHM_TYPES = [
	'sha256',
	'sha384',
	'sha512',
	'sha1',
] as const
export const WEBHOOK_AVAILABLE_SECRET_ENCODING_FORMATS = ['hex', 'base64', 'alphanumeric'] as const
export const WEBHOOK_VALID_SECRET_BYTE_LENGTHS = [16, 32, 64] as const
export type WebhookSupportedHmacAlgorithmType =
	(typeof WEBHOOK_SUPPORTED_HMAC_ALGORITHM_TYPES)[number]
export type WebhookAvailableSecretEncodingFormat =
	(typeof WEBHOOK_AVAILABLE_SECRET_ENCODING_FORMATS)[number]
export type WebhookValidSecretByteLength = (typeof WEBHOOK_VALID_SECRET_BYTE_LENGTHS)[number]
export interface WebhookSecretsGenerationOptions {
	count?: number
	length?: WebhookValidSecretByteLength
	algorithm?: WebhookSupportedHmacAlgorithmType
	format?: WebhookAvailableSecretEncodingFormat
	includeSignature?: boolean
	includeTimestamp?: boolean
}
export interface WebhookGeneratedSecret {
	secret: string
	signature?: string
	timestamp?: number
}
export interface WebhookSecretsGenerationResult {
	secrets: WebhookGeneratedSecret[]
	metadata: {
		count: number
		length: WebhookValidSecretByteLength
		algorithm: WebhookSupportedHmacAlgorithmType
		format: WebhookAvailableSecretEncodingFormat
		includeSignature: boolean
		includeTimestamp: boolean
	}
}
const WEBHOOK_GENERATION_MINIMUM_COUNT = 1
const WEBHOOK_GENERATION_MAXIMUM_COUNT = 10
const WEBHOOK_SIGNATURE_DEFAULT_PAYLOAD_STRING = 'webhook-payload'
const WEBHOOK_BASE32_ENCODING_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
function webhookEncodeBufferToBase32Alphabet(webhookBuffer: Buffer): string {
	let bits = 0
	let value = 0
	let output = ''
	for (let i = 0; i < webhookBuffer.length; i++) {
		const byte = webhookBuffer[i]!
		value = (value << 8) | byte
		bits += 8
		while (bits >= 5) {
			const index = (value >>> (bits - 5)) & 31
			output += WEBHOOK_BASE32_ENCODING_ALPHABET[index]
			bits -= 5
		}
	}
	if (bits > 0) {
		const index = (value << (5 - bits)) & 31
		output += WEBHOOK_BASE32_ENCODING_ALPHABET[index]
	}
	return output
}
const webhookFormatToEncoderFunctionMap: Record<
	WebhookAvailableSecretEncodingFormat,
	(buf: Buffer) => string
> = {
	hex: (webhookBuffer) => webhookBuffer.toString('hex'),
	base64: (webhookBuffer) => webhookBuffer.toString('base64').replace(/=+$/, ''),
	alphanumeric: webhookEncodeBufferToBase32Alphabet,
}
function webhookComputeHmacSignatureForSecret(
	webhookPayload: string,
	webhookSecretBuffer: Buffer,
	webhookAlgorithm: WebhookSupportedHmacAlgorithmType,
	webhookFormat: WebhookAvailableSecretEncodingFormat,
): string {
	const webhookHmac = createHmac(webhookAlgorithm, webhookSecretBuffer)
	webhookHmac.update(webhookPayload)
	const webhookSignatureBytes = webhookHmac.digest()
	return webhookFormatToEncoderFunctionMap[webhookFormat](webhookSignatureBytes)
}
function webhookValidateAndNormalizeGenerationOptions(
	webhookOptions: WebhookSecretsGenerationOptions,
): Required<WebhookSecretsGenerationOptions> {
	const webhookCount = webhookOptions.count ?? 1
	if (
		!Number.isInteger(webhookCount) ||
		webhookCount < WEBHOOK_GENERATION_MINIMUM_COUNT ||
		webhookCount > WEBHOOK_GENERATION_MAXIMUM_COUNT
	) {
		throw new ValidationError(
			`count must be an integer between ${WEBHOOK_GENERATION_MINIMUM_COUNT} and ${WEBHOOK_GENERATION_MAXIMUM_COUNT}`,
			{ count: webhookCount },
		)
	}
	const webhookLength = webhookOptions.length ?? 32
	if (!WEBHOOK_VALID_SECRET_BYTE_LENGTHS.includes(webhookLength)) {
		throw new ValidationError(
			`length must be one of: ${WEBHOOK_VALID_SECRET_BYTE_LENGTHS.join(', ')}`,
			{
				length: webhookLength,
			},
		)
	}
	const webhookAlgorithm = webhookOptions.algorithm ?? 'sha256'
	if (!WEBHOOK_SUPPORTED_HMAC_ALGORITHM_TYPES.includes(webhookAlgorithm)) {
		throw new ValidationError(
			`algorithm must be one of: ${WEBHOOK_SUPPORTED_HMAC_ALGORITHM_TYPES.join(', ')}`,
			{
				algorithm: webhookAlgorithm,
			},
		)
	}
	const webhookFormat = webhookOptions.format ?? 'hex'
	if (!WEBHOOK_AVAILABLE_SECRET_ENCODING_FORMATS.includes(webhookFormat)) {
		throw new ValidationError(
			`format must be one of: ${WEBHOOK_AVAILABLE_SECRET_ENCODING_FORMATS.join(', ')}`,
			{
				format: webhookFormat,
			},
		)
	}
	const webhookIncludeSignature = webhookOptions.includeSignature ?? false
	const webhookIncludeTimestamp = webhookOptions.includeTimestamp ?? false
	return {
		count: webhookCount,
		length: webhookLength,
		algorithm: webhookAlgorithm,
		format: webhookFormat,
		includeSignature: webhookIncludeSignature,
		includeTimestamp: webhookIncludeTimestamp,
	}
}
function webhookGenerateSingleWebhookSecret(
	webhookLength: WebhookValidSecretByteLength,
	webhookAlgorithm: WebhookSupportedHmacAlgorithmType,
	webhookFormat: WebhookAvailableSecretEncodingFormat,
	webhookIncludeSignature: boolean,
	webhookIncludeTimestamp: boolean,
): WebhookGeneratedSecret {
	const webhookSecretBytes = randomBytes(webhookLength)
	const webhookSecret = webhookFormatToEncoderFunctionMap[webhookFormat](webhookSecretBytes)
	const webhookResult: WebhookGeneratedSecret = { secret: webhookSecret }
	if (webhookIncludeSignature) {
		webhookResult.signature = webhookComputeHmacSignatureForSecret(
			WEBHOOK_SIGNATURE_DEFAULT_PAYLOAD_STRING,
			webhookSecretBytes,
			webhookAlgorithm,
			webhookFormat,
		)
	}
	if (webhookIncludeTimestamp) {
		webhookResult.timestamp = Math.floor(Date.now() / 1000)
	}
	return webhookResult
}
export function webhookGenerateSecrets(
	webhookOptions: WebhookSecretsGenerationOptions = {},
): WebhookSecretsGenerationResult {
	const {
		count: webhookCount,
		length: webhookLength,
		algorithm: webhookAlgorithm,
		format: webhookFormat,
		includeSignature: webhookIncludeSignature,
		includeTimestamp: webhookIncludeTimestamp,
	} = webhookValidateAndNormalizeGenerationOptions(webhookOptions)
	const webhookSecrets = Array.from({ length: webhookCount }, () =>
		webhookGenerateSingleWebhookSecret(
			webhookLength,
			webhookAlgorithm,
			webhookFormat,
			webhookIncludeSignature,
			webhookIncludeTimestamp,
		),
	)
	return {
		secrets: webhookSecrets,
		metadata: {
			count: webhookCount,
			length: webhookLength,
			algorithm: webhookAlgorithm,
			format: webhookFormat,
			includeSignature: webhookIncludeSignature,
			includeTimestamp: webhookIncludeTimestamp,
		},
	}
}
export function webhookExportSecrets(
	webhookResult: WebhookSecretsGenerationResult,
	webhookExportFormat: 'json' | 'txt' | 'csv' = 'json',
): string {
	const { secrets: webhookSecrets, metadata: webhookMetadata } = webhookResult
	switch (webhookExportFormat) {
		case 'json':
			return JSON.stringify({ metadata: webhookMetadata, secrets: webhookSecrets }, null, 2)
		case 'txt': {
			return webhookSecrets
				.map((webhookSingleSecret) => {
					const webhookLines = [`secret: ${webhookSingleSecret.secret}`]
					if (webhookSingleSecret.signature)
						webhookLines.push(`signature: ${webhookSingleSecret.signature}`)
					if (webhookSingleSecret.timestamp)
						webhookLines.push(`timestamp: ${webhookSingleSecret.timestamp}`)
					return webhookLines.join('\n')
				})
				.join('\n\n')
		}
		case 'csv': {
			const webhookHasSignature = webhookSecrets.some(
				(webhookSingleSecret) => webhookSingleSecret.signature,
			)
			const webhookHasTimestamp = webhookSecrets.some(
				(webhookSingleSecret) => webhookSingleSecret.timestamp,
			)
			const webhookHeaders = ['secret']
			if (webhookHasSignature) webhookHeaders.push('signature')
			if (webhookHasTimestamp) webhookHeaders.push('timestamp')
			const webhookEscapeCsv = (webhookValue: string | number) => {
				const webhookString = String(webhookValue)
				if (
					webhookString.includes('"') ||
					webhookString.includes(',') ||
					webhookString.includes('\n')
				) {
					return `"${webhookString.replace(/"/g, '""')}"`
				}
				return webhookString
			}
			const webhookRows = webhookSecrets.map((webhookSingleSecret) => {
				const webhookCols = [webhookEscapeCsv(webhookSingleSecret.secret)]
				if (webhookHasSignature)
					webhookCols.push(
						webhookSingleSecret.signature
							? webhookEscapeCsv(webhookSingleSecret.signature)
							: '',
					)
				if (webhookHasTimestamp)
					webhookCols.push(
						webhookSingleSecret.timestamp
							? webhookEscapeCsv(webhookSingleSecret.timestamp)
							: '',
					)
				return webhookCols.join(',')
			})
			return webhookHeaders.join(',') + '\n' + webhookRows.join('\n')
		}
		default:
			throw new ValidationError(`Unsupported export format: ${webhookExportFormat}`)
	}
}
export function webhookGenerateSingleSampleSecret(): WebhookGeneratedSecret {
	const webhookSampleResult = webhookGenerateSecrets({
		count: 1,
		length: 32,
		algorithm: 'sha256',
		format: 'hex',
		includeSignature: false,
		includeTimestamp: false,
	})
	return webhookSampleResult.secrets[0]!
}
