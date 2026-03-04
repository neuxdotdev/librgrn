import { randomInt } from 'crypto'
import { ValidationError } from '../../../error.js'
export const PASSWORD_GENERATOR_MIN_LENGTH = 4
export const PASSWORD_GENERATOR_MAX_LENGTH = 128
export const PASSWORD_GENERATOR_DEFAULT_LENGTH = 16
export const PASSWORD_GENERATOR_MIN_COUNT = 1
export const PASSWORD_GENERATOR_MAX_COUNT = 25
export const PASSWORD_GENERATOR_DEFAULT_COUNT = 1
export const PASSWORD_GENERATOR_MAX_GENERATION_ATTEMPTS = 10000
export const PASSWORD_GENERATOR_UPPERCASE_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
export const PASSWORD_GENERATOR_LOWERCASE_CHARS = 'abcdefghijklmnopqrstuvwxyz'
export const PASSWORD_GENERATOR_NUMBER_CHARS = '0123456789'
export const PASSWORD_GENERATOR_SYMBOL_CHARS = '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
export const PASSWORD_GENERATOR_SIMILAR_CHARS = '0O1lI2Z5S8B'
export const PASSWORD_GENERATOR_AMBIGUOUS_CHARS = '0O1lI'
export const PASSWORD_GENERATOR_ENTROPY_THRESHOLDS = Object.freeze([
	{ min: 0, max: 39, label: 'weak' as const },
	{ min: 40, max: 79, label: 'medium' as const },
	{ min: 80, max: 119, label: 'strong' as const },
	{ min: 120, max: 159, label: 'very_strong' as const },
	{ min: 160, max: Infinity, label: 'very_strong' as const },
] as const)
export const PASSWORD_GENERATOR_SUPPORTED_EXPORT_FORMATS = Object.freeze([
	'json',
	'txt',
	'csv',
] as const)
export const PASSWORD_GENERATOR_VALIDATION_PATTERNS = Object.freeze({
	hasUppercase: /[A-Z]/,
	hasLowercase: /[a-z]/,
	hasNumber: /[0-9]/,
	hasSymbol: /[!"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~]/,
	hasWhitespace: /\s/,
	hasRepeatingChars: /(.)\1{2,}/,
	hasSequentialChars:
		/(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)/i,
} as const)
export type PasswordGeneratorStrength = 'weak' | 'medium' | 'strong' | 'very_strong'
export type PasswordGeneratorExportFormat =
	(typeof PASSWORD_GENERATOR_SUPPORTED_EXPORT_FORMATS)[number]
export type PasswordGeneratorCharacterSet = 'uppercase' | 'lowercase' | 'numbers' | 'symbols'
export interface PasswordGeneratorGenerateOptions {
	count?: number
	length?: number
	useUppercase?: boolean
	useLowercase?: boolean
	useNumbers?: boolean
	useSymbols?: boolean
	excludeSimilar?: boolean
	excludeChars?: string | readonly string[]
	requireAllTypes?: boolean
	minUppercase?: number
	minLowercase?: number
	minNumbers?: number
	minSymbols?: number
	excludeWhitespace?: boolean
	excludeSequential?: boolean
	excludeRepeating?: number
}
export interface PasswordGeneratorItem {
	readonly passwordGenerator: string
}
export interface PasswordGeneratorValidationResult {
	readonly isValid: boolean
	readonly strength: PasswordGeneratorStrength
	readonly entropyBits: number
	readonly length: number
	readonly hasUppercase: boolean
	readonly hasLowercase: boolean
	readonly hasNumber: boolean
	readonly hasSymbol: boolean
	readonly hasWhitespace: boolean
	readonly hasRepeatingChars: boolean
	readonly hasSequentialChars: boolean
	readonly errors: readonly string[]
	readonly warnings: readonly string[]
}
export interface PasswordGeneratorGenerateMetadata {
	readonly count: number
	readonly length: number
	readonly useUppercase: boolean
	readonly useLowercase: boolean
	readonly useNumbers: boolean
	readonly useSymbols: boolean
	readonly excludeSimilar: boolean
	readonly excludeChars?: string
	readonly poolSize: number
	readonly entropyBits: number
	readonly strength: PasswordGeneratorStrength
	readonly requireAllTypes: boolean
	readonly minUppercase: number
	readonly minLowercase: number
	readonly minNumbers: number
	readonly minSymbols: number
	readonly excludeSequential: boolean
	readonly excludeRepeating: number
}
export interface PasswordGeneratorGenerateResult {
	readonly passwordsGenerator: readonly PasswordGeneratorItem[]
	readonly metadata: PasswordGeneratorGenerateMetadata
}
function passwordValidateOptions(
	options: PasswordGeneratorGenerateOptions = {},
): Required<Omit<PasswordGeneratorGenerateOptions, 'excludeChars'>> & { excludeChars: string } {
	const count = options.count ?? PASSWORD_GENERATOR_DEFAULT_COUNT
	if (
		!Number.isInteger(count) ||
		count < PASSWORD_GENERATOR_MIN_COUNT ||
		count > PASSWORD_GENERATOR_MAX_COUNT
	) {
		throw new ValidationError(
			`count must be an integer between ${PASSWORD_GENERATOR_MIN_COUNT} and ${PASSWORD_GENERATOR_MAX_COUNT}`,
			{ count },
		)
	}
	const length = options.length ?? PASSWORD_GENERATOR_DEFAULT_LENGTH
	if (
		!Number.isInteger(length) ||
		length < PASSWORD_GENERATOR_MIN_LENGTH ||
		length > PASSWORD_GENERATOR_MAX_LENGTH
	) {
		throw new ValidationError(
			`length must be an integer between ${PASSWORD_GENERATOR_MIN_LENGTH} and ${PASSWORD_GENERATOR_MAX_LENGTH}`,
			{ length },
		)
	}
	const useUppercase = options.useUppercase ?? true
	const useLowercase = options.useLowercase ?? true
	const useNumbers = options.useNumbers ?? true
	const useSymbols = options.useSymbols ?? true
	const excludeSimilar = options.excludeSimilar ?? false
	const requireAllTypes = options.requireAllTypes ?? false
	const excludeWhitespace = options.excludeWhitespace ?? true
	const excludeSequential = options.excludeSequential ?? false
	const excludeRepeating = options.excludeRepeating ?? 0
	const minUppercase = options.minUppercase ?? 0
	const minLowercase = options.minLowercase ?? 0
	const minNumbers = options.minNumbers ?? 0
	const minSymbols = options.minSymbols ?? 0
	if (typeof useUppercase !== 'boolean') {
		throw new ValidationError('useUppercase must be a boolean', { useUppercase })
	}
	if (typeof useLowercase !== 'boolean') {
		throw new ValidationError('useLowercase must be a boolean', { useLowercase })
	}
	if (typeof useNumbers !== 'boolean') {
		throw new ValidationError('useNumbers must be a boolean', { useNumbers })
	}
	if (typeof useSymbols !== 'boolean') {
		throw new ValidationError('useSymbols must be a boolean', { useSymbols })
	}
	if (typeof excludeSimilar !== 'boolean') {
		throw new ValidationError('excludeSimilar must be a boolean', { excludeSimilar })
	}
	if (typeof requireAllTypes !== 'boolean') {
		throw new ValidationError('requireAllTypes must be a boolean', { requireAllTypes })
	}
	if (typeof excludeWhitespace !== 'boolean') {
		throw new ValidationError('excludeWhitespace must be a boolean', { excludeWhitespace })
	}
	if (typeof excludeSequential !== 'boolean') {
		throw new ValidationError('excludeSequential must be a boolean', { excludeSequential })
	}
	if (!Number.isInteger(excludeRepeating) || excludeRepeating < 0) {
		throw new ValidationError('excludeRepeating must be a non-negative integer', {
			excludeRepeating,
		})
	}
	if (!Number.isInteger(minUppercase) || minUppercase < 0) {
		throw new ValidationError('minUppercase must be a non-negative integer', { minUppercase })
	}
	if (!Number.isInteger(minLowercase) || minLowercase < 0) {
		throw new ValidationError('minLowercase must be a non-negative integer', { minLowercase })
	}
	if (!Number.isInteger(minNumbers) || minNumbers < 0) {
		throw new ValidationError('minNumbers must be a non-negative integer', { minNumbers })
	}
	if (!Number.isInteger(minSymbols) || minSymbols < 0) {
		throw new ValidationError('minSymbols must be a non-negative integer', { minSymbols })
	}
	const minRequired = minUppercase + minLowercase + minNumbers + minSymbols
	if (minRequired > length) {
		throw new ValidationError(
			`Sum of minimum character requirements (${minRequired}) exceeds passwordGenerator length (${length})`,
			{ minRequired, length },
		)
	}
	let excludeCharsStr = ''
	if (options.excludeChars !== undefined) {
		if (Array.isArray(options.excludeChars)) {
			for (const ch of options.excludeChars) {
				if (typeof ch !== 'string' || ch.length !== 1) {
					throw new ValidationError(
						'excludeChars array must contain single-character strings',
						{ invalid: ch },
					)
				}
			}
			excludeCharsStr = options.excludeChars.join('')
		} else if (typeof options.excludeChars === 'string') {
			excludeCharsStr = options.excludeChars
		} else {
			throw new ValidationError('excludeChars must be a string or array of strings', {
				excludeChars: options.excludeChars,
			})
		}
	}
	if (!useUppercase && !useLowercase && !useNumbers && !useSymbols) {
		throw new ValidationError('At least one character set must be selected', {
			useUppercase,
			useLowercase,
			useNumbers,
			useSymbols,
		})
	}
	return {
		count,
		length,
		useUppercase,
		useLowercase,
		useNumbers,
		useSymbols,
		excludeSimilar,
		excludeChars: excludeCharsStr,
		requireAllTypes,
		excludeWhitespace,
		excludeSequential,
		excludeRepeating,
		minUppercase,
		minLowercase,
		minNumbers,
		minSymbols,
	}
}
function passwordBuildCharacterPool(
	options: Required<Omit<PasswordGeneratorGenerateOptions, 'excludeChars'>> & {
		excludeChars: string
	},
): string {
	let pool = ''
	if (options.useUppercase) pool += PASSWORD_GENERATOR_UPPERCASE_CHARS
	if (options.useLowercase) pool += PASSWORD_GENERATOR_LOWERCASE_CHARS
	if (options.useNumbers) pool += PASSWORD_GENERATOR_NUMBER_CHARS
	if (options.useSymbols) pool += PASSWORD_GENERATOR_SYMBOL_CHARS
	const excludeSet = new Set(options.excludeChars)
	if (options.excludeSimilar) {
		for (const ch of PASSWORD_GENERATOR_SIMILAR_CHARS) {
			excludeSet.add(ch)
		}
	}
	if (options.excludeWhitespace) {
		for (const ch of ' \t\n\r') {
			excludeSet.add(ch)
		}
	}
	if (excludeSet.size > 0) {
		pool = pool
			.split('')
			.filter((ch) => !excludeSet.has(ch))
			.join('')
	}
	if (pool.length === 0) {
		throw new ValidationError('Character pool is empty after exclusions', {
			excludeSimilar: options.excludeSimilar,
			excludeChars: options.excludeChars,
			excludeWhitespace: options.excludeWhitespace,
		})
	}
	return pool
}
function passwordCalculateEntropy(poolSize: number, length: number): number {
	if (poolSize <= 0 || length <= 0) return 0
	const entropy = length * Math.log2(poolSize)
	return Math.round(entropy * 10) / 10
}
function passwordGetStrength(entropyBits: number): PasswordGeneratorStrength {
	const threshold = PASSWORD_GENERATOR_ENTROPY_THRESHOLDS.find(
		(t) => entropyBits >= t.min && entropyBits <= t.max,
	)
	return threshold?.label ?? 'weak'
}
function passwordCountCharTypes(passwordGenerator: string): {
	uppercase: number
	lowercase: number
	numbers: number
	symbols: number
} {
	let uppercase = 0
	let lowercase = 0
	let numbers = 0
	let symbols = 0
	for (const ch of passwordGenerator) {
		if (/[A-Z]/.test(ch)) uppercase++
		else if (/[a-z]/.test(ch)) lowercase++
		else if (/[0-9]/.test(ch)) numbers++
		else if (/[!"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~]/.test(ch)) symbols++
	}
	return { uppercase, lowercase, numbers, symbols }
}
function passwordHasRepeatingChars(passwordGenerator: string, maxRepeat: number): boolean {
	if (maxRepeat <= 0) return false
	let count = 1
	for (let i = 1; i < passwordGenerator.length; i++) {
		if (passwordGenerator[i] === passwordGenerator[i - 1]) {
			count++
			if (count > maxRepeat) return true
		} else {
			count = 1
		}
	}
	return false
}
function passwordHasSequentialChars(passwordGenerator: string): boolean {
	const lower = passwordGenerator.toLowerCase()
	for (let i = 0; i < lower.length - 2; i++) {
		const c1 = lower.charCodeAt(i)
		const c2 = lower.charCodeAt(i + 1)
		const c3 = lower.charCodeAt(i + 2)
		if (c2 === c1 + 1 && c3 === c2 + 1) return true
		if (c2 === c1 - 1 && c3 === c2 - 1) return true
	}
	return false
}
function passwordSatisfiesRequirements(
	passwordGenerator: string,
	options: Required<Omit<PasswordGeneratorGenerateOptions, 'excludeChars'>> & {
		excludeChars: string
	},
): boolean {
	const charTypes = passwordCountCharTypes(passwordGenerator)
	if (charTypes.uppercase < options.minUppercase) return false
	if (charTypes.lowercase < options.minLowercase) return false
	if (charTypes.numbers < options.minNumbers) return false
	if (charTypes.symbols < options.minSymbols) return false
	if (options.excludeSequential && passwordHasSequentialChars(passwordGenerator)) return false
	if (
		options.excludeRepeating > 0 &&
		passwordHasRepeatingChars(passwordGenerator, options.excludeRepeating)
	)
		return false
	return true
}
function* passwordGenerateItems(
	count: number,
	pool: string,
	length: number,
	options: Required<Omit<PasswordGeneratorGenerateOptions, 'excludeChars'>> & {
		excludeChars: string
	},
): Generator<PasswordGeneratorItem, void, unknown> {
	const poolArray = pool.split('')
	const poolSize = poolArray.length
	const maxAttempts = PASSWORD_GENERATOR_MAX_GENERATION_ATTEMPTS
	for (let i = 0; i < count; i++) {
		let attempts = 0
		let passwordGenerator = ''
		let satisfied = false
		while (!satisfied && attempts < maxAttempts) {
			let pwd = ''
			for (let j = 0; j < length; j++) {
				const idx = randomInt(0, poolSize)
				pwd += poolArray[idx]!
			}
			if (!options.requireAllTypes) {
				if (passwordSatisfiesRequirements(pwd, options)) {
					passwordGenerator = pwd
					satisfied = true
				}
			} else {
				if (passwordSatisfiesRequirements(pwd, options)) {
					passwordGenerator = pwd
					satisfied = true
				}
			}
			attempts++
		}
		if (!satisfied) {
			throw new ValidationError(
				`Failed to generate passwordGenerator after ${maxAttempts} attempts. Constraints may be too strict.`,
				{
					useUppercase: options.useUppercase,
					useLowercase: options.useLowercase,
					useNumbers: options.useNumbers,
					useSymbols: options.useSymbols,
					requireAllTypes: options.requireAllTypes,
					length,
					minUppercase: options.minUppercase,
					minLowercase: options.minLowercase,
					minNumbers: options.minNumbers,
					minSymbols: options.minSymbols,
				},
			)
		}
		yield { passwordGenerator }
	}
}
function passwordBuildMetadata(
	validated: Required<Omit<PasswordGeneratorGenerateOptions, 'excludeChars'>> & {
		excludeChars: string
	},
	poolSize: number,
	entropyBits: number,
	strength: PasswordGeneratorStrength,
): PasswordGeneratorGenerateMetadata {
	const base = {
		count: validated.count,
		length: validated.length,
		useUppercase: validated.useUppercase,
		useLowercase: validated.useLowercase,
		useNumbers: validated.useNumbers,
		useSymbols: validated.useSymbols,
		excludeSimilar: validated.excludeSimilar,
		poolSize,
		entropyBits,
		strength,
		requireAllTypes: validated.requireAllTypes,
		minUppercase: validated.minUppercase,
		minLowercase: validated.minLowercase,
		minNumbers: validated.minNumbers,
		minSymbols: validated.minSymbols,
		excludeSequential: validated.excludeSequential,
		excludeRepeating: validated.excludeRepeating,
	}
	if (validated.excludeChars && validated.excludeChars.length > 0) {
		return { ...base, excludeChars: validated.excludeChars }
	}
	return base
}
export function passwordGenerateTokens(
	options: PasswordGeneratorGenerateOptions = {},
): PasswordGeneratorGenerateResult {
	const validated = passwordValidateOptions(options)
	const pool = passwordBuildCharacterPool(validated)
	const generator = passwordGenerateItems(validated.count, pool, validated.length, validated)
	const passwordsGenerator: PasswordGeneratorItem[] = []
	for (const item of generator) {
		passwordsGenerator.push(item)
	}
	const entropyBits = passwordCalculateEntropy(pool.length, validated.length)
	const strength = passwordGetStrength(entropyBits)
	const metadata = passwordBuildMetadata(validated, pool.length, entropyBits, strength)
	return {
		passwordsGenerator: Object.freeze(passwordsGenerator),
		metadata: Object.freeze(metadata),
	}
}
export function passwordGenerateSample(): PasswordGeneratorItem {
	const result = passwordGenerateTokens({ count: 1, length: PASSWORD_GENERATOR_DEFAULT_LENGTH })
	return result.passwordsGenerator[0]!
}
export function passwordGenerateOne(options: PasswordGeneratorGenerateOptions = {}): string {
	const result = passwordGenerateTokens({ ...options, count: 1 })
	return result.passwordsGenerator[0]?.passwordGenerator ?? ''
}
export function passwordGenerateStrong(
	options: Partial<PasswordGeneratorGenerateOptions> = {},
): PasswordGeneratorItem {
	const result = passwordGenerateTokens({
		count: 1,
		length: options.length ?? 20,
		useUppercase: true,
		useLowercase: true,
		useNumbers: true,
		useSymbols: true,
		requireAllTypes: true,
		excludeSimilar: options.excludeSimilar ?? true,
		excludeSequential: options.excludeSequential ?? true,
		excludeRepeating: options.excludeRepeating ?? 3,
		minUppercase: 2,
		minLowercase: 2,
		minNumbers: 2,
		minSymbols: 2,
		...options,
	})
	return result.passwordsGenerator[0]!
}
export function passwordValidate(
	passwordGenerator: string,
	options: PasswordGeneratorGenerateOptions = {},
): PasswordGeneratorValidationResult {
	const errors: string[] = []
	const warnings: string[] = []
	const minLength = options.length ?? PASSWORD_GENERATOR_MIN_LENGTH
	if (passwordGenerator.length < minLength) {
		errors.push(`Password must be at least ${minLength} characters`)
	}
	if (!passwordGenerator || typeof passwordGenerator !== 'string') {
		return {
			isValid: false,
			strength: 'weak' as const,
			entropyBits: 0,
			length: 0,
			hasUppercase: false,
			hasLowercase: false,
			hasNumber: false,
			hasSymbol: false,
			hasWhitespace: false,
			hasRepeatingChars: false,
			hasSequentialChars: false,
			errors: ['PasswordGenerator is empty or invalid'],
			warnings: [],
		}
	}
	const length = passwordGenerator.length
	const hasUppercase = PASSWORD_GENERATOR_VALIDATION_PATTERNS.hasUppercase.test(passwordGenerator)
	const hasLowercase = PASSWORD_GENERATOR_VALIDATION_PATTERNS.hasLowercase.test(passwordGenerator)
	const hasNumber = PASSWORD_GENERATOR_VALIDATION_PATTERNS.hasNumber.test(passwordGenerator)
	const hasSymbol = PASSWORD_GENERATOR_VALIDATION_PATTERNS.hasSymbol.test(passwordGenerator)
	const hasWhitespace =
		PASSWORD_GENERATOR_VALIDATION_PATTERNS.hasWhitespace.test(passwordGenerator)
	const hasRepeatingChars =
		PASSWORD_GENERATOR_VALIDATION_PATTERNS.hasRepeatingChars.test(passwordGenerator)
	const hasSequentialChars =
		PASSWORD_GENERATOR_VALIDATION_PATTERNS.hasSequentialChars.test(passwordGenerator)
	if (length < PASSWORD_GENERATOR_MIN_LENGTH) {
		errors.push(
			`PasswordGenerator must be at least ${PASSWORD_GENERATOR_MIN_LENGTH} characters`,
		)
	}
	if (length < 8) {
		warnings.push('PasswordGenerator is shorter than recommended (8 characters)')
	}
	if (!hasUppercase) {
		errors.push('PasswordGenerator must contain at least one uppercase letter')
	}
	if (!hasLowercase) {
		errors.push('PasswordGenerator must contain at least one lowercase letter')
	}
	if (!hasNumber) {
		errors.push('PasswordGenerator must contain at least one number')
	}
	if (!hasSymbol) {
		errors.push('PasswordGenerator must contain at least one symbol')
	}
	if (hasWhitespace) {
		warnings.push('PasswordGenerator contains whitespace characters')
	}
	if (hasRepeatingChars) {
		warnings.push('PasswordGenerator contains repeating characters (3+ consecutive)')
	}
	if (hasSequentialChars) {
		warnings.push('PasswordGenerator contains sequential characters')
	}
	let poolSize = 0
	if (hasUppercase) poolSize += PASSWORD_GENERATOR_UPPERCASE_CHARS.length
	if (hasLowercase) poolSize += PASSWORD_GENERATOR_LOWERCASE_CHARS.length
	if (hasNumber) poolSize += PASSWORD_GENERATOR_NUMBER_CHARS.length
	if (hasSymbol) poolSize += PASSWORD_GENERATOR_SYMBOL_CHARS.length
	if (poolSize === 0) poolSize = 95
	const entropyBits = passwordCalculateEntropy(poolSize, length)
	const strength = passwordGetStrength(entropyBits)
	if (strength === 'weak') {
		errors.push('PasswordGenerator strength is too weak')
	} else if (strength === 'medium') {
		warnings.push('PasswordGenerator strength could be improved')
	}
	return {
		isValid: errors.length === 0,
		strength,
		entropyBits,
		length,
		hasUppercase,
		hasLowercase,
		hasNumber,
		hasSymbol,
		hasWhitespace,
		hasRepeatingChars,
		hasSequentialChars,
		errors: Object.freeze(errors),
		warnings: Object.freeze(warnings),
	}
}
export function passwordIsStrong(passwordGenerator: string, minEntropy: number = 80): boolean {
	const result = passwordValidate(passwordGenerator)
	return result.isValid && result.entropyBits >= minEntropy
}
export function passwordStrengthFromString(
	passwordGenerator: string,
	includeSymbols: boolean = true,
): { entropyBits: number; strength: PasswordGeneratorStrength } {
	if (!passwordGenerator || typeof passwordGenerator !== 'string') {
		throw new ValidationError('PasswordGenerator must be a non-empty string', {
			passwordGenerator,
		})
	}
	let poolSize = 0
	if (/[A-Z]/.test(passwordGenerator)) poolSize += PASSWORD_GENERATOR_UPPERCASE_CHARS.length
	if (/[a-z]/.test(passwordGenerator)) poolSize += PASSWORD_GENERATOR_LOWERCASE_CHARS.length
	if (/[0-9]/.test(passwordGenerator)) poolSize += PASSWORD_GENERATOR_NUMBER_CHARS.length
	if (includeSymbols && /[!"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~]/.test(passwordGenerator)) {
		poolSize += PASSWORD_GENERATOR_SYMBOL_CHARS.length
	}
	if (poolSize === 0) poolSize = 95
	const entropyBits = passwordCalculateEntropy(poolSize, passwordGenerator.length)
	const strength = passwordGetStrength(entropyBits)
	return { entropyBits, strength }
}
export function passwordExportTokens(
	result: PasswordGeneratorGenerateResult,
	format: PasswordGeneratorExportFormat = 'json',
): string {
	const { passwordsGenerator, metadata } = result
	switch (format) {
		case 'json':
			return JSON.stringify({ metadata, passwordsGenerator }, null, 2)
		case 'txt':
			return passwordsGenerator.map((p) => p.passwordGenerator).join('\n')
		case 'csv': {
			const escapeCsv = (str: string): string => {
				if (str.includes('"') || str.includes(',') || str.includes('\n')) {
					return `"${str.replace(/"/g, '""')}"`
				}
				return str
			}
			const header = 'passwordGenerator'
			const rows = passwordsGenerator.map((p) => escapeCsv(p.passwordGenerator))
			return [header, ...rows].join('\n')
		}
		default:
			throw new ValidationError(`Unsupported export format: ${format}`, { format })
	}
}
export function passwordExportToEnv(
	result: PasswordGeneratorGenerateResult,
	prefix: string = 'PASSWORD_GENERATOR',
): string {
	const { passwordsGenerator } = result
	return passwordsGenerator
		.map((p, i) => `${prefix}_${i + 1}="${p.passwordGenerator}"`)
		.join('\n')
}
export class PasswordGeneratorGenerator {
	private readonly options: Required<Omit<PasswordGeneratorGenerateOptions, 'excludeChars'>> & {
		excludeChars: string
	}
	private readonly pool: string
	private readonly entropyBits: number
	private readonly strength: PasswordGeneratorStrength
	constructor(options: PasswordGeneratorGenerateOptions = {}) {
		this.options = passwordValidateOptions(options)
		this.pool = passwordBuildCharacterPool(this.options)
		this.entropyBits = passwordCalculateEntropy(this.pool.length, this.options.length)
		this.strength = passwordGetStrength(this.entropyBits)
	}
	public generate(): PasswordGeneratorGenerateResult {
		const generator = passwordGenerateItems(
			this.options.count,
			this.pool,
			this.options.length,
			this.options,
		)
		const passwordsGenerator: PasswordGeneratorItem[] = []
		for (const item of generator) {
			passwordsGenerator.push(item)
		}
		const metadata = passwordBuildMetadata(
			this.options,
			this.pool.length,
			this.entropyBits,
			this.strength,
		)
		return {
			passwordsGenerator: Object.freeze(passwordsGenerator),
			metadata: Object.freeze(metadata),
		}
	}
	public generateOne(): string {
		const result = this.generate()
		return result.passwordsGenerator[0]?.passwordGenerator ?? ''
	}
	public generateStrong(): PasswordGeneratorItem {
		const strongOptions: PasswordGeneratorGenerateOptions = {
			count: 1,
			length: Math.max(this.options.length, 20),
			useUppercase: true,
			useLowercase: true,
			useNumbers: true,
			useSymbols: true,
			requireAllTypes: true,
			excludeSimilar: true,
			excludeSequential: true,
			excludeRepeating: 3,
			minUppercase: 2,
			minLowercase: 2,
			minNumbers: 2,
			minSymbols: 2,
		}
		const generator = passwordGenerateItems(
			strongOptions.count!,
			this.pool,
			strongOptions.length!,
			passwordValidateOptions(strongOptions),
		)
		const passwordsGenerator: PasswordGeneratorItem[] = []
		for (const item of generator) {
			passwordsGenerator.push(item)
		}
		return passwordsGenerator[0]!
	}
	public export(
		result: PasswordGeneratorGenerateResult,
		format: PasswordGeneratorExportFormat = 'json',
	): string {
		return passwordExportTokens(result, format)
	}
	public exportToEnv(
		result: PasswordGeneratorGenerateResult,
		prefix: string = 'PASSWORD_GENERATOR',
	): string {
		return passwordExportToEnv(result, prefix)
	}
	public validate(passwordGenerator: string): PasswordGeneratorValidationResult {
		return passwordValidate(passwordGenerator, this.options)
	}
	public isStrong(passwordGenerator: string, minEntropy: number = 80): boolean {
		return passwordIsStrong(passwordGenerator, minEntropy)
	}
	public getPoolSize(): number {
		return this.pool.length
	}
	public getEntropyBits(): number {
		return this.entropyBits
	}
	public getStrength(): PasswordGeneratorStrength {
		return this.strength
	}
	public getOptions(): Readonly<
		Required<Omit<PasswordGeneratorGenerateOptions, 'excludeChars'>> & {
			excludeChars: string
		}
	> {
		return Object.freeze({ ...this.options })
	}
}
export const passwordPresets = Object.freeze({
	basic: {
		length: 10,
		useUppercase: true,
		useLowercase: true,
		useNumbers: true,
		useSymbols: false,
		requireAllTypes: false,
	} as PasswordGeneratorGenerateOptions,
	standard: {
		length: 14,
		useUppercase: true,
		useLowercase: true,
		useNumbers: true,
		useSymbols: true,
		requireAllTypes: true,
		excludeSimilar: true,
	} as PasswordGeneratorGenerateOptions,
	strong: {
		length: 18,
		useUppercase: true,
		useLowercase: true,
		useNumbers: true,
		useSymbols: true,
		requireAllTypes: true,
		excludeSimilar: true,
		excludeSequential: true,
		excludeRepeating: 3,
		minUppercase: 2,
		minLowercase: 2,
		minNumbers: 2,
		minSymbols: 2,
	} as PasswordGeneratorGenerateOptions,
	maximum: {
		length: 24,
		useUppercase: true,
		useLowercase: true,
		useNumbers: true,
		useSymbols: true,
		requireAllTypes: true,
		excludeSimilar: true,
		excludeSequential: true,
		excludeRepeating: 2,
		minUppercase: 3,
		minLowercase: 3,
		minNumbers: 3,
		minSymbols: 3,
	} as PasswordGeneratorGenerateOptions,
	pin: {
		length: 6,
		useUppercase: false,
		useLowercase: false,
		useNumbers: true,
		useSymbols: false,
		requireAllTypes: false,
	} as PasswordGeneratorGenerateOptions,
	apiKey: {
		length: 32,
		useUppercase: true,
		useLowercase: true,
		useNumbers: true,
		useSymbols: false,
		requireAllTypes: true,
		excludeSimilar: true,
	} as PasswordGeneratorGenerateOptions,
} as const)
export type PasswordGeneratorPreset = keyof typeof passwordPresets
export function passwordGenerateWithPreset(
	preset: PasswordGeneratorPreset,
	overrides: Partial<PasswordGeneratorGenerateOptions> = {},
): PasswordGeneratorGenerateResult {
	const baseOptions = passwordPresets[preset]
	return passwordGenerateTokens({ ...baseOptions, ...overrides })
}
