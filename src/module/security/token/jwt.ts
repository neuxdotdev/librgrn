import jwt, { SignOptions, VerifyOptions, Algorithm } from 'jsonwebtoken'
import { randomInt, randomUUID } from 'crypto'
import { ValidationError, CryptoError } from './../../../error.js'
import type { StringValue } from 'ms'

export type JwtAlgorithm = 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512'
export interface JwtSignConfig {
  algorithm: JwtAlgorithm
  key: string | Buffer
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
}
const SUPPORTED_ALGORITHMS: JwtAlgorithm[] = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512']
function assertAlgorithm(alg: string): asserts alg is JwtAlgorithm {
  if (!SUPPORTED_ALGORITHMS.includes(alg as JwtAlgorithm)) {
    throw new ValidationError(`Unsupported algorithm: ${alg}`, { alg })
  }
}
export function signJwt<T extends object = any>(payload: T, config: JwtSignConfig): string {
  assertAlgorithm(config.algorithm)
  if (!config.key) throw new ValidationError('Signing key is required')
  const options: SignOptions = {}
  if (config.algorithm) options.algorithm = config.algorithm as Algorithm
  if (config.issuer !== undefined) options.issuer = config.issuer
  if (config.audience !== undefined) options.audience = config.audience
  if (config.expiresIn !== undefined) options.expiresIn = config.expiresIn
  if (config.notBefore !== undefined) options.notBefore = config.notBefore
  try {
    return jwt.sign(payload, config.key, options)
  } catch (err: any) {
    throw new CryptoError('JWT signing failed', { algorithm: config.algorithm }, err)
  }
}
export function verifyJwt<T extends object = any>(token: string, config: JwtVerifyConfig): T {
  assertAlgorithm(config.algorithm)
  const options: VerifyOptions = { algorithms: [config.algorithm] }
  if (config.issuer !== undefined) options.issuer = config.issuer
  if (config.audience !== undefined) options.audience = config.audience as any
  if (config.clockTolerance !== undefined) options.clockTolerance = config.clockTolerance
  if (config.maxAge !== undefined) options.maxAge = config.maxAge
  try {
    return jwt.verify(token, config.key, options) as T
  } catch (err: any) {
    throw new CryptoError('JWT verification failed', { algorithm: config.algorithm }, err)
  }
}
export function decodeJwt<T = any>(token: string): T | null {
  return jwt.decode(token) as T | null
}
export interface RandomPayloadOptions {
  includeRoles?: boolean
  includeScope?: boolean
  issuer?: string
  audience?: string
}
export function generateRandomPayload(options: RandomPayloadOptions = {}): Record<string, any> {
  const payload: Record<string, any> = {}
  payload['jti'] = randomUUID()
  const userId = randomInt(1000, 9999)
  payload['sub'] = `user_${userId}`

  if (options.includeRoles) {
    const rolesPool = ['admin', 'user', 'editor', 'viewer']
    const count = randomInt(1, 4)
    const roles: string[] = []
    while (roles.length < count) {
      const role = rolesPool[randomInt(0, rolesPool.length)]
      if (typeof role === 'string' && !roles.includes(role)) {
        roles.push(role)
      }
    }
    payload['roles'] = roles
  }
  if (options.includeScope) {
    const scopesPool = ['read', 'write', 'delete', 'update']
    const count = randomInt(1, 4)
    const scopes: string[] = []
    while (scopes.length < count) {
      const scope = scopesPool[randomInt(0, scopesPool.length)]
      if (typeof scope === 'string' && !scopes.includes(scope)) {
        scopes.push(scope)
      }
    }
    payload['scope'] = scopes.join(' ')
  }
  return payload
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
  privateKey?: string | Buffer
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
export function generateJWTs(options: JwtGenerateOptions): JwtGenerateResult {
  if (!options.key) throw new ValidationError('Key is required for token generation')
  const {
    count = 1,
    algorithm = 'HS256',
    expiresIn = 3600,
    includeRoles = false,
    includeScope = false,
    issuer = 'api.example.com',
    audience = 'https://api.example.com',
    key,
  } = options
  if (count < 1 || count > 100)
    throw new ValidationError('count must be between 1 and 100', { count })
  assertAlgorithm(algorithm)
  const tokens: JwtGeneratedToken[] = []
  for (let i = 0; i < count; i++) {
    const payload = generateRandomPayload({
      includeRoles,
      includeScope,
      issuer,
      audience,
    })
    const now = Math.floor(Date.now() / 1000)
    payload['iat'] = now
    const token = signJwt(payload, {
      algorithm,
      key,
      issuer,
      audience,
      expiresIn,
    })
    tokens.push({ token, payload })
  }
  return {
    tokens,
    metadata: { algorithm, expiresIn, count, includeRoles, includeScope },
  }
}
export function exportTokens(
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
