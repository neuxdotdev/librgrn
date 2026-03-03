import { randomInt } from 'crypto'
import { ValidationError } from '../../../error.js'
export const PIN_VALID_LENGTHS = [4, 6, 8] as const
export const PIN_MIN_COUNT = 1
export const PIN_MAX_COUNT = 100
export const PIN_MAX_GENERATION_ATTEMPTS = 1000
export type PinLength = (typeof PIN_VALID_LENGTHS)[number]
export interface PinGenerateOptions {
	count?: number
	length?: PinLength
	uniqueDigits?: boolean
	excludeRepeating?: boolean
	excludeSequential?: boolean
	excludeZero?: boolean
}
export interface PinItem {
	pin: string
}
export interface PinGenerateResult {
	pins: readonly PinItem[]
	metadata: {
		count: number
		length: PinLength
		uniqueDigits: boolean
		excludeRepeating: boolean
		excludeSequential: boolean
		excludeZero: boolean
	}
}
const pinSequentialPatterns = (() => {
	const patterns = new Set<string>()
	for (let start = 0; start <= 7; start++) {
		patterns.add(`${start}${start + 1}${start + 2}`)
	}
	for (let start = 9; start >= 2; start--) {
		patterns.add(`${start}${start - 1}${start - 2}`)
	}
	return patterns
})()
function pinHasSequentialDigits(pin: string): boolean {
	for (let i = 0; i <= pin.length - 3; i++) {
		const substring = pin.slice(i, i + 3)
		if (pinSequentialPatterns.has(substring)) return true
	}
	return false
}
function pinHasConsecutiveRepeatingDigits(pin: string): boolean {
	for (let i = 0; i < pin.length - 1; i++) {
		if (pin[i] === pin[i + 1]) return true
	}
	return false
}
function pinHasAllUniqueDigits(pin: string): boolean {
	const digitSet = new Set(pin)
	return digitSet.size === pin.length
}
function pinContainsZero(pin: string): boolean {
	return pin.includes('0')
}
function pinGenerateSingleItem(
	length: PinLength,
	uniqueDigits: boolean,
	excludeRepeating: boolean,
	excludeSequential: boolean,
	excludeZero: boolean,
): string {
	let attempts = 0
	while (attempts < PIN_MAX_GENERATION_ATTEMPTS) {
		attempts++
		let pin = ''
		for (let i = 0; i < length; i++) {
			const digit = excludeZero ? randomInt(1, 10) : randomInt(0, 10)
			pin += digit.toString()
		}
		if (uniqueDigits && !pinHasAllUniqueDigits(pin)) continue
		if (excludeRepeating && pinHasConsecutiveRepeatingDigits(pin)) continue
		if (excludeSequential && pinHasSequentialDigits(pin)) continue
		if (excludeZero && pinContainsZero(pin)) continue
		return pin
	}
	throw new ValidationError(
		`PIN generation failed after ${PIN_MAX_GENERATION_ATTEMPTS} attempts. Constraints may be too strict.`,
		{ length, uniqueDigits, excludeRepeating, excludeSequential, excludeZero },
	)
}
interface PinValidationRule {
	validate: (value: any) => void
}
function pinCreateValidator<T extends PinGenerateOptions>(rules: {
	[K in keyof T]?: PinValidationRule
}) {
	return (options: T): Required<Pick<T, keyof T>> => {
		const result: any = {}
		for (const key in rules) {
			const rule = rules[key]
			const defaultValue = (() => {
				switch (key) {
					case 'count':
						return PIN_MIN_COUNT
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
const pinValidateOptions = pinCreateValidator<PinGenerateOptions>({
	count: {
		validate: (val) => {
			if (!Number.isInteger(val) || val < PIN_MIN_COUNT || val > PIN_MAX_COUNT) {
				throw new ValidationError(
					`count must be an integer between ${PIN_MIN_COUNT} and ${PIN_MAX_COUNT}`,
					{ count: val },
				)
			}
		},
	},
	length: {
		validate: (val) => {
			if (!PIN_VALID_LENGTHS.includes(val)) {
				throw new ValidationError(
					`length must be one of: ${PIN_VALID_LENGTHS.join(', ')}`,
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
function* pinGenerateItems(
	count: number,
	length: PinLength,
	uniqueDigits: boolean,
	excludeRepeating: boolean,
	excludeSequential: boolean,
	excludeZero: boolean,
): Generator<PinItem, void, unknown> {
	for (let i = 0; i < count; i++) {
		const pin = pinGenerateSingleItem(
			length,
			uniqueDigits,
			excludeRepeating,
			excludeSequential,
			excludeZero,
		)
		yield { pin }
	}
}
function pinCollectGenerator<T>(generator: Generator<T>): T[] {
	const collected: T[] = []
	for (const item of generator) {
		collected.push(item)
	}
	return collected
}
export function pinGenerateTokens(options: PinGenerateOptions = {}): PinGenerateResult {
	const { count, length, uniqueDigits, excludeRepeating, excludeSequential, excludeZero } =
		pinValidateOptions(options)
	const generator = pinGenerateItems(
		count,
		length,
		uniqueDigits,
		excludeRepeating,
		excludeSequential,
		excludeZero,
	)
	const pins = pinCollectGenerator(generator)
	const metadata: PinGenerateResult['metadata'] = {
		count,
		length,
		uniqueDigits,
		excludeRepeating,
		excludeSequential,
		excludeZero,
	}
	return { pins, metadata }
}
export function pinExportTokens(
	result: PinGenerateResult,
	exportFormat: 'json' | 'txt' | 'csv' = 'json',
): string {
	const { pins, metadata } = result
	switch (exportFormat) {
		case 'json':
			return JSON.stringify({ metadata, pins }, null, 2)
		case 'txt':
			return pins.map((item) => item.pin).join('\n')
		case 'csv': {
			const headers = ['pin']
			const escapeCsv = (str: string): string => {
				if (str.includes('"') || str.includes(',') || str.includes('\n')) {
					return `"${str.replace(/"/g, '""')}"`
				}
				return str
			}
			const rows = pins.map((item) => escapeCsv(item.pin))
			return headers.join(',') + '\n' + rows.join('\n')
		}
		default:
			throw new ValidationError(`Unsupported export format: ${exportFormat}`)
	}
}
export function pinGenerateSample(): PinItem {
	const result = pinGenerateTokens({ count: 1, length: 4 })
	return result.pins[0]!
}
export function pinGenerateAtmPins(count: number = 1): PinGenerateResult {
	return pinGenerateTokens({ count, length: 4, excludeZero: false })
}
export function pinGenerateAuthPins(count: number = 1): PinGenerateResult {
	return pinGenerateTokens({ count, length: 6, excludeZero: false })
}
export function pinGenerateSecurePins(count: number = 1): PinGenerateResult {
	return pinGenerateTokens({ count, length: 8, excludeZero: false })
}
export class PinGenerator {
	private readonly options: ReturnType<typeof pinValidateOptions>
	constructor(options: PinGenerateOptions = {}) {
		this.options = pinValidateOptions(options)
	}
	public pinGenerate(): PinGenerateResult {
		const { count, length, uniqueDigits, excludeRepeating, excludeSequential, excludeZero } =
			this.options
		const generator = pinGenerateItems(
			count,
			length,
			uniqueDigits,
			excludeRepeating,
			excludeSequential,
			excludeZero,
		)
		const pins = pinCollectGenerator(generator)
		const metadata: PinGenerateResult['metadata'] = {
			count,
			length,
			uniqueDigits,
			excludeRepeating,
			excludeSequential,
			excludeZero,
		}
		return { pins, metadata }
	}
	public pinExport(
		result: PinGenerateResult,
		exportFormat: 'json' | 'txt' | 'csv' = 'json',
	): string {
		return pinExportTokens(result, exportFormat)
	}
}
