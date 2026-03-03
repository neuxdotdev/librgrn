import jwt, { SignOptions, VerifyOptions, Algorithm } from 'jsonwebtoken'
import { randomInt, randomUUID } from 'crypto'
import { ValidationError, CryptoError } from './../../../error.js'
import type { StringValue } from 'ms'
export type JwtHmacAlgorithm = 'HS256' | 'HS384' | 'HS512'
export type JwtRsaAlgorithm = 'RS256' | 'RS384' | 'RS512'
export type JwtAlgorithm = JwtHmacAlgorithm | JwtRsaAlgorithm
export interface JwtSignConfig {
	algorithm: JwtAlgorithm
	key: string | Buffer
	keyid?: string
	issuer?: string
	audience?: string | string[]
	expiresIn?: number | StringValue
	notBefore?: number | StringValue
}
export interface JwtVerifyConfig {
	algorithm: JwtAlgorithm
	key: string | Buffer
	issuer?: string
	audience?: string
	clockTolerance?: number
	maxAge?: string | number
	requireIssuer?: boolean
	requireAudience?: boolean
}
export interface JwtPayloadOptions {
	includeRoles?: boolean
	includeScope?: boolean
}
export interface JwtGenerateOptions {
	count?: number
	algorithm?: JwtAlgorithm
	expiresIn?: number
	includeRoles?: boolean
	includeScope?: boolean
	issuer?: string
	audience?: string
	key: string | Buffer
}
export interface JwtGeneratedToken {
	token: string
	payload: Record<string, any>
}
export interface JwtGenerateResult {
	tokens: JwtGeneratedToken[]
	metadata: {
		algorithm: JwtAlgorithm
		expiresIn: number
		count: number
		includeRoles: boolean
		includeScope: boolean
	}
}
interface JwtPayloadBase {
	jti: string
	sub: string
	roles?: string[]
	scope?: string
	iat?: number
}
interface JwtDecodedClaims {
	iss?: string
	aud?: string | string[]
	[key: string]: unknown
}
const JWT_SUPPORTED_ALGORITHMS: JwtAlgorithm[] = [
	'HS256',
	'HS384',
	'HS512',
	'RS256',
	'RS384',
	'RS512',
]
const JWT_DEFAULT_CLOCK_TOLERANCE = 5
const JWT_GENERATION_MIN_COUNT = 1
const JWT_GENERATION_MAX_COUNT = 100
const JWT_DEFAULT_EXPIRES_IN = 3600
function jwtAssertAlgorithm(alg: string): asserts alg is JwtAlgorithm {
	if (!JWT_SUPPORTED_ALGORITHMS.includes(alg as JwtAlgorithm)) {
		throw new ValidationError(`Unsupported algorithm: ${alg}`, { alg })
	}
}
function jwtValidateKeyForAlgorithm(
	algorithm: JwtAlgorithm,
	key: unknown,
	operation: 'sign' | 'verify',
): asserts key is string | Buffer {
	if (!key) {
		throw new ValidationError('Key is required', { algorithm, operation })
	}
	if (algorithm.startsWith('RS')) {
		const keyStr = key.toString()
		if (operation === 'sign') {
			if (
				!keyStr.includes('BEGIN PRIVATE KEY') &&
				!keyStr.includes('BEGIN RSA PRIVATE KEY')
			) {
				throw new ValidationError('RSA signing requires a private key in PEM format', {
					algorithm,
				})
			}
		} else {
			if (!keyStr.includes('BEGIN PUBLIC KEY')) {
				throw new ValidationError('RSA verification requires a public key in PEM format', {
					algorithm,
				})
			}
		}
	}
}
function jwtBuildSignOptions(config: JwtSignConfig): SignOptions {
	const options: SignOptions = {
		algorithm: config.algorithm as Algorithm,
	}
	if (config.keyid) options.keyid = config.keyid
	if (config.issuer !== undefined) options.issuer = config.issuer
	if (config.audience !== undefined) options.audience = config.audience
	if (config.expiresIn !== undefined) options.expiresIn = config.expiresIn
	if (config.notBefore !== undefined) options.notBefore = config.notBefore
	return options
}
function jwtBuildVerifyOptions(config: JwtVerifyConfig): VerifyOptions {
	const options: VerifyOptions = {
		algorithms: [config.algorithm as Algorithm],
		clockTolerance: config.clockTolerance ?? JWT_DEFAULT_CLOCK_TOLERANCE,
	}
	if (config.issuer !== undefined) options.issuer = config.issuer
	if (config.audience !== undefined) options.audience = config.audience
	if (config.maxAge !== undefined) options.maxAge = config.maxAge
	return options
}
function jwtEnforceStrictClaims(decoded: JwtDecodedClaims, config: JwtVerifyConfig): void {
	const requireIssuer = config.requireIssuer !== false
	const requireAudience = config.requireAudience !== false
	if (requireIssuer) {
		if (!decoded.iss || decoded.iss !== config.issuer) {
			throw new CryptoError('Missing or mismatched issuer', {
				expected: config.issuer,
				actual: decoded.iss,
			})
		}
	}
	if (requireAudience) {
		const actualAud = decoded.aud
		const expectedAud = config.audience
		if (
			!actualAud ||
			(Array.isArray(actualAud)
				? !actualAud.includes(expectedAud as string)
				: actualAud !== expectedAud)
		) {
			throw new CryptoError('Missing or mismatched audience', {
				expected: expectedAud,
				actual: actualAud,
			})
		}
	}
}
function jwtShuffle<T>(array: T[]): T[] {
	const result = [...array]
	for (let i = result.length - 1; i > 0; i--) {
		const j = Math.floor(Math.random() * (i + 1))
		;[result[i]!, result[j]!] = [result[j]!, result[i]!]
	}
	return result
}
function jwtResolveGenerateOptions(options: JwtGenerateOptions): Required<JwtGenerateOptions> {
	if (!options?.key) {
		throw new ValidationError('Key is required for token generation')
	}
	const count = options.count ?? JWT_GENERATION_MIN_COUNT
	if (count < JWT_GENERATION_MIN_COUNT || count > JWT_GENERATION_MAX_COUNT) {
		throw new ValidationError(
			`count must be between ${JWT_GENERATION_MIN_COUNT} and ${JWT_GENERATION_MAX_COUNT}`,
			{ count },
		)
	}
	const algorithm = options.algorithm ?? 'HS256'
	jwtAssertAlgorithm(algorithm)
	return {
		key: options.key,
		count,
		algorithm,
		expiresIn: options.expiresIn ?? JWT_DEFAULT_EXPIRES_IN,
		includeRoles: options.includeRoles ?? false,
		includeScope: options.includeScope ?? false,
		issuer: options.issuer ?? '',
		audience: options.audience ?? '',
	}
}
function jwtGenerateSingleToken(
	config: Required<JwtGenerateOptions>,
	now: number,
): JwtGeneratedToken {
	const payload = jwtGeneratePayload({
		includeRoles: config.includeRoles,
		includeScope: config.includeScope,
	})
	payload.iat = now
	const token = jwtSign(payload, {
		algorithm: config.algorithm,
		key: config.key,
		issuer: config.issuer,
		audience: config.audience,
		expiresIn: config.expiresIn,
	})
	return { token, payload }
}
function jwtGetUnixTimestamp(): number {
	return Math.floor(Date.now() / 1000)
}
export function jwtSign<T extends object = any>(payload: T, config: JwtSignConfig): string {
	jwtAssertAlgorithm(config.algorithm)
	jwtValidateKeyForAlgorithm(config.algorithm, config.key, 'sign')
	const options = jwtBuildSignOptions(config)
	try {
		return jwt.sign(payload, config.key, options)
	} catch (err: any) {
		throw new CryptoError('JWT signing failed', { algorithm: config.algorithm }, err)
	}
}
export function jwtVerify<T extends object = any>(
	token: string,
	config: JwtVerifyConfig,
	validate?: (payload: unknown) => T,
): T {
	jwtAssertAlgorithm(config.algorithm)
	jwtValidateKeyForAlgorithm(config.algorithm, config.key, 'verify')
	const options = jwtBuildVerifyOptions(config)
	let decoded: unknown
	try {
		decoded = jwt.verify(token, config.key, options)
	} catch (err: any) {
		throw new CryptoError('JWT verification failed', { algorithm: config.algorithm }, err)
	}
	if (typeof decoded !== 'object' || decoded === null) {
		throw new CryptoError('Invalid JWT payload: not an object')
	}
	jwtEnforceStrictClaims(decoded as JwtDecodedClaims, config)
	if (validate) {
		return validate(decoded)
	}
	return decoded as T
}
export function jwtDecode<T = any>(token: string): T | null {
	return jwt.decode(token) as T | null
}
export function jwtGeneratePayload(
	options: JwtPayloadOptions = {},
): JwtPayloadBase & Record<string, any> {
	const payload: JwtPayloadBase = {
		jti: randomUUID(),
		sub: `user_${randomInt(1000, 9999)}`,
	}
	if (options.includeRoles) {
		const rolesPool = ['admin', 'user', 'editor', 'viewer']
		const count = randomInt(1, 4)
		const shuffled = jwtShuffle(rolesPool)
		payload.roles = shuffled.slice(0, count)
	}
	if (options.includeScope) {
		const scopesPool = ['read', 'write', 'delete', 'update']
		const count = randomInt(1, 4)
		const shuffled = jwtShuffle(scopesPool)
		payload.scope = shuffled.slice(0, count).join(' ')
	}
	return payload
}
export function jwtGenerateTokens(options: JwtGenerateOptions): JwtGenerateResult {
	const config = jwtResolveGenerateOptions(options)
	const now = jwtGetUnixTimestamp()
	const tokens = Array.from({ length: config.count }, () => jwtGenerateSingleToken(config, now))
	return {
		tokens,
		metadata: {
			algorithm: config.algorithm,
			expiresIn: config.expiresIn,
			count: config.count,
			includeRoles: config.includeRoles,
			includeScope: config.includeScope,
		},
	}
}
export function jwtExportTokens(
	result: JwtGenerateResult,
	format: 'json' | 'csv' | 'txt' = 'json',
): string {
	const { tokens, metadata } = result
	switch (format) {
		case 'json':
			return JSON.stringify({ metadata, tokens }, null, 2)
		case 'txt':
			return tokens.map((t) => t.token).join('\n')
		case 'csv': {
			const header = 'token,payload\n'
			const rows = tokens
				.map((t) => {
					const payloadStr = JSON.stringify(t.payload).replace(/"/g, '""')
					return `"${t.token}","${payloadStr}"`
				})
				.join('\n')
			return header + rows
		}
		default:
			throw new ValidationError('Unsupported export format', { format })
	}
}
