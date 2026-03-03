const ERROR_DEFAULT_MESSAGE = 'An unknown error occurred'
const ERROR_DEFAULT_CODE = 'UNKNOWN_ERROR'
const ERROR_DEFAULT_AUTH_MESSAGE = 'Authentication failed'
const ERROR_DEFAULT_TOKEN_MESSAGE = 'Token error'
const ERROR_DEFAULT_CRYPTO_MESSAGE = 'Cryptography operation failed'
const ERROR_DEFAULT_VALIDATION_MESSAGE = 'Validation failed'
const ERROR_DEFAULT_PIN_MESSAGE = 'PIN is invalid'
const ERROR_DEFAULT_PASSWORD_MESSAGE = 'Password is weak'
export type ErrorCode =
	| 'AUTH_INVALID'
	| 'AUTH_EXPIRED'
	| 'TOKEN_INVALID'
	| 'TOKEN_EXPIRED'
	| 'CRYPTO_FAIL'
	| 'VALIDATION_ERROR'
	| 'PIN_INVALID'
	| 'PASSWORD_WEAK'
	| 'UNKNOWN_ERROR'
export interface ErrorOptions {
	message?: string
	code?: ErrorCode
	meta?: Record<string, unknown> | undefined
	cause?: Error | undefined
}
export class LibrgrnError extends Error {
	public readonly code: ErrorCode
	public readonly meta: Record<string, unknown> | undefined
	public readonly cause: Error | undefined
	constructor(options: ErrorOptions) {
		super(options.message ?? ERROR_DEFAULT_MESSAGE)
		Object.setPrototypeOf(this, new.target.prototype)
		this.name = this.constructor.name
		this.code = options.code ?? ERROR_DEFAULT_CODE
		this.meta = options.meta
		this.cause = options.cause
		if ((Error as any).captureStackTrace) {
			;(Error as any).captureStackTrace(this, this.constructor)
		}
	}
	public toJSON(): Record<string, unknown> {
		return {
			name: this.name,
			message: this.message,
			code: this.code,
			meta: this.meta,
			cause: this.cause ? { name: this.cause.name, message: this.cause.message } : undefined,
			stack: this.stack,
		}
	}
}
export class AuthError extends LibrgrnError {
	constructor(message?: string, meta?: Record<string, unknown>, cause?: Error) {
		super({
			message: message ?? ERROR_DEFAULT_AUTH_MESSAGE,
			code: 'AUTH_INVALID',
			meta,
			cause,
		})
	}
}
export class TokenError extends LibrgrnError {
	constructor(message?: string, meta?: Record<string, unknown>, cause?: Error) {
		super({
			message: message ?? ERROR_DEFAULT_TOKEN_MESSAGE,
			code: 'TOKEN_INVALID',
			meta,
			cause,
		})
	}
}
export class CryptoError extends LibrgrnError {
	constructor(message?: string, meta?: Record<string, unknown>, cause?: Error) {
		super({
			message: message ?? ERROR_DEFAULT_CRYPTO_MESSAGE,
			code: 'CRYPTO_FAIL',
			meta,
			cause,
		})
	}
}
export class ValidationError extends LibrgrnError {
	constructor(message?: string, meta?: Record<string, unknown>, cause?: Error) {
		super({
			message: message ?? ERROR_DEFAULT_VALIDATION_MESSAGE,
			code: 'VALIDATION_ERROR',
			meta,
			cause,
		})
	}
}
export class PinError extends LibrgrnError {
	constructor(message?: string, meta?: Record<string, unknown>, cause?: Error) {
		super({
			message: message ?? ERROR_DEFAULT_PIN_MESSAGE,
			code: 'PIN_INVALID',
			meta,
			cause,
		})
	}
}
export class PasswordError extends LibrgrnError {
	constructor(message?: string, meta?: Record<string, unknown>, cause?: Error) {
		super({
			message: message ?? ERROR_DEFAULT_PASSWORD_MESSAGE,
			code: 'PASSWORD_WEAK',
			meta,
			cause,
		})
	}
}
export const errorThrow = (error: LibrgrnError): never => {
	console.error(JSON.stringify(error.toJSON(), null, 2))
	throw error
}
export const errorWrap = (fn: () => void, fallback: ErrorOptions): void => {
	try {
		fn()
	} catch (err) {
		throw new LibrgrnError({
			...fallback,
			cause: err instanceof Error ? err : undefined,
		})
	}
}
