import { randomInt } from 'crypto'
import { ValidationError } from '../../../error.js'
export const PIN_GENERATOR_VALID_LENGTHS = [4, 6, 8] as const
export const PIN_GENERATOR_MIN_COUNT = 1
export const PIN_GENERATOR_MAX_COUNT = 100
export const PIN_GENERATOR_MAX_GENERATION_ATTEMPTS = 1000
export type PinGeneratorLength = (typeof PIN_GENERATOR_VALID_LENGTHS)[number]
export interface PinGeneratorGenerateOptions {
	count?: number
	length?: PinGeneratorLength
	uniqueDigits?: boolean
	excludeRepeating?: boolean
	excludeSequential?: boolean
	excludeZero?: boolean
}
export interface PinGeneratorItem {
	pinGenerator: string
}
export interface PinGeneratorGenerateResult {
	pinGenerators: readonly PinGeneratorItem[]
	metadata: {
		count: number
		length: PinGeneratorLength
		uniqueDigits: boolean
		excludeRepeating: boolean
		excludeSequential: boolean
		excludeZero: boolean
	}
}
const pinGeneratorSequentialPatterns = (() => {
	const patterns = new Set<string>()
	for (let start = 0; start <= 7; start++) {
		patterns.add(`${start}${start + 1}${start + 2}`)
	}
	for (let start = 9; start >= 2; start--) {
		patterns.add(`${start}${start - 1}${start - 2}`)
	}
	return patterns
})()
function pinGeneratorHasSequentialDigits(pinGenerator: string): boolean {
	for (let i = 0; i <= pinGenerator.length - 3; i++) {
		const substring = pinGenerator.slice(i, i + 3)
		if (pinGeneratorSequentialPatterns.has(substring)) return true
	}
	return false
}
function pinGeneratorHasConsecutiveRepeatingDigits(pinGenerator: string): boolean {
	for (let i = 0; i < pinGenerator.length - 1; i++) {
		if (pinGenerator[i] === pinGenerator[i + 1]) return true
	}
	return false
}
function pinGeneratorHasAllUniqueDigits(pinGenerator: string): boolean {
	const digitSet = new Set(pinGenerator)
	return digitSet.size === pinGenerator.length
}
function pinGeneratorContainsZero(pinGenerator: string): boolean {
	return pinGenerator.includes('0')
}
function pinGeneratorGenerateSingleItem(
	length: PinGeneratorLength,
	uniqueDigits: boolean,
	excludeRepeating: boolean,
	excludeSequential: boolean,
	excludeZero: boolean,
): string {
	let attempts = 0
	while (attempts < PIN_GENERATOR_MAX_GENERATION_ATTEMPTS) {
		attempts++
		let pinGenerator = ''
		for (let i = 0; i < length; i++) {
			const digit = excludeZero ? randomInt(1, 10) : randomInt(0, 10)
			pinGenerator += digit.toString()
		}
		if (uniqueDigits && !pinGeneratorHasAllUniqueDigits(pinGenerator)) continue
		if (excludeRepeating && pinGeneratorHasConsecutiveRepeatingDigits(pinGenerator)) continue
		if (excludeSequential && pinGeneratorHasSequentialDigits(pinGenerator)) continue
		if (excludeZero && pinGeneratorContainsZero(pinGenerator)) continue
		return pinGenerator
	}
	throw new ValidationError(
		`PIN_GENERATOR generation failed after ${PIN_GENERATOR_MAX_GENERATION_ATTEMPTS} attempts. Constraints may be too strict.`,
		{ length, uniqueDigits, excludeRepeating, excludeSequential, excludeZero },
	)
}
interface PinGeneratorValidationRule {
	validate: (value: any) => void
}
function pinGeneratorCreateValidator<T extends PinGeneratorGenerateOptions>(rules: {
	[K in keyof T]?: PinGeneratorValidationRule
}) {
	return (options: T): Required<Pick<T, keyof T>> => {
		const result: any = {}
		for (const key in rules) {
			const rule = rules[key]
			const defaultValue = (() => {
				switch (key) {
					case 'count':
						return PIN_GENERATOR_MIN_COUNT
					case 'length':
						return 4
					case 'uniqueDigits':
						return false
					case 'excludeRepeating':
						return false
					case 'excludeSequential':
						return false
					case 'excludeZero':
						return false
					default:
						return undefined
				}
			})()
			const value = options[key] ?? defaultValue
			if (rule?.validate) {
				rule.validate(value)
			}
			result[key] = value
		}
		return result
	}
}
const pinGeneratorValidateOptions = pinGeneratorCreateValidator<PinGeneratorGenerateOptions>({
	count: {
		validate: (val) => {
			if (
				!Number.isInteger(val) ||
				val < PIN_GENERATOR_MIN_COUNT ||
				val > PIN_GENERATOR_MAX_COUNT
			) {
				throw new ValidationError(
					`count must be an integer between ${PIN_GENERATOR_MIN_COUNT} and ${PIN_GENERATOR_MAX_COUNT}`,
					{ count: val },
				)
			}
		},
	},
	length: {
		validate: (val) => {
			if (!PIN_GENERATOR_VALID_LENGTHS.includes(val)) {
				throw new ValidationError(
					`length must be one of: ${PIN_GENERATOR_VALID_LENGTHS.join(', ')}`,
					{ length: val },
				)
			}
		},
	},
	uniqueDigits: {
		validate: (val) => {
			if (typeof val !== 'boolean') {
				throw new ValidationError('uniqueDigits must be a boolean', { uniqueDigits: val })
			}
		},
	},
	excludeRepeating: {
		validate: (val) => {
			if (typeof val !== 'boolean') {
				throw new ValidationError('excludeRepeating must be a boolean', {
					excludeRepeating: val,
				})
			}
		},
	},
	excludeSequential: {
		validate: (val) => {
			if (typeof val !== 'boolean') {
				throw new ValidationError('excludeSequential must be a boolean', {
					excludeSequential: val,
				})
			}
		},
	},
	excludeZero: {
		validate: (val) => {
			if (typeof val !== 'boolean') {
				throw new ValidationError('excludeZero must be a boolean', { excludeZero: val })
			}
		},
	},
})
function* pinGeneratorGenerateItems(
	count: number,
	length: PinGeneratorLength,
	uniqueDigits: boolean,
	excludeRepeating: boolean,
	excludeSequential: boolean,
	excludeZero: boolean,
): Generator<PinGeneratorItem, void, unknown> {
	for (let i = 0; i < count; i++) {
		const pinGenerator = pinGeneratorGenerateSingleItem(
			length,
			uniqueDigits,
			excludeRepeating,
			excludeSequential,
			excludeZero,
		)
		yield { pinGenerator }
	}
}
function pinGeneratorCollectGenerator<T>(generator: Generator<T>): T[] {
	const collected: T[] = []
	for (const item of generator) {
		collected.push(item)
	}
	return collected
}
export function pinGeneratorGenerateTokens(
	options: PinGeneratorGenerateOptions = {},
): PinGeneratorGenerateResult {
	const { count, length, uniqueDigits, excludeRepeating, excludeSequential, excludeZero } =
		pinGeneratorValidateOptions(options)
	const generator = pinGeneratorGenerateItems(
		count,
		length,
		uniqueDigits,
		excludeRepeating,
		excludeSequential,
		excludeZero,
	)
	const pinGenerators = pinGeneratorCollectGenerator(generator)
	const metadata: PinGeneratorGenerateResult['metadata'] = {
		count,
		length,
		uniqueDigits,
		excludeRepeating,
		excludeSequential,
		excludeZero,
	}
	return { pinGenerators, metadata }
}
export function pinGeneratorExportTokens(
	result: PinGeneratorGenerateResult,
	exportFormat: 'json' | 'txt' | 'csv' = 'json',
): string {
	const { pinGenerators, metadata } = result
	switch (exportFormat) {
		case 'json':
			return JSON.stringify({ metadata, pinGenerators }, null, 2)
		case 'txt':
			return pinGenerators.map((item) => item.pinGenerator).join('\n')
		case 'csv': {
			const headers = ['pinGenerator']
			const escapeCsv = (str: string): string => {
				if (str.includes('"') || str.includes(',') || str.includes('\n')) {
					return `"${str.replace(/"/g, '""')}"`
				}
				return str
			}
			const rows = pinGenerators.map((item) => escapeCsv(item.pinGenerator))
			return headers.join(',') + '\n' + rows.join('\n')
		}
		default:
			throw new ValidationError(`Unsupported export format: ${exportFormat}`)
	}
}
export function pinGeneratorGenerateSample(): PinGeneratorItem {
	const result = pinGeneratorGenerateTokens({ count: 1, length: 4 })
	return result.pinGenerators[0]!
}
export function pinGeneratorGenerateAtmPinGenerators(
	count: number = 1,
): PinGeneratorGenerateResult {
	return pinGeneratorGenerateTokens({ count, length: 4, excludeZero: false })
}
export function pinGeneratorGenerateAuthPinGenerators(
	count: number = 1,
): PinGeneratorGenerateResult {
	return pinGeneratorGenerateTokens({ count, length: 6, excludeZero: false })
}
export function pinGeneratorGenerateSecurePinGenerators(
	count: number = 1,
): PinGeneratorGenerateResult {
	return pinGeneratorGenerateTokens({ count, length: 8, excludeZero: false })
}
export class PinGeneratorGenerator {
	private readonly options: ReturnType<typeof pinGeneratorValidateOptions>
	constructor(options: PinGeneratorGenerateOptions = {}) {
		this.options = pinGeneratorValidateOptions(options)
	}
	public pinGeneratorGenerate(): PinGeneratorGenerateResult {
		const { count, length, uniqueDigits, excludeRepeating, excludeSequential, excludeZero } =
			this.options
		const generator = pinGeneratorGenerateItems(
			count,
			length,
			uniqueDigits,
			excludeRepeating,
			excludeSequential,
			excludeZero,
		)
		const pinGenerators = pinGeneratorCollectGenerator(generator)
		const metadata: PinGeneratorGenerateResult['metadata'] = {
			count,
			length,
			uniqueDigits,
			excludeRepeating,
			excludeSequential,
			excludeZero,
		}
		return { pinGenerators, metadata }
	}
	public pinGeneratorExport(
		result: PinGeneratorGenerateResult,
		exportFormat: 'json' | 'txt' | 'csv' = 'json',
	): string {
		return pinGeneratorExportTokens(result, exportFormat)
	}
}
