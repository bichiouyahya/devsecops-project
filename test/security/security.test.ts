/*
 * Security unit tests (DevSecOps project, Task 5)
 *
 * Each test states a security property the application MUST have.
 * Juice Shop is deliberately vulnerable, so these tests failed at first: that was the proof
 * the flaws exist. Fixed flaws (SQL injection, JWT alg none) are now enforced as regression
 * tests: if one comes back, the pipeline fails. Flaws not fixed yet are marked "todo":
 * they still run and show in the report, but do not block.
 *
 * Threat model links (docs/threat-model):
 *   - "SQL injection bypasses login"            -> Login SQL injection tests
 *   - "JWT forgery with a hardcoded signing key" -> Forged token test
 *   - "IDOR on basket API"                      -> Basket access control test
 *   - "Error responses leak stack traces"       -> Error handling test
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from '../api/helpers/setup'
import { login } from '../api/helpers/auth'

const jsonHeader = { 'content-type': 'application/json' }
let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('Security: login must resist SQL injection (OWASP A05 Injection)', () => {
  const payloads = [
    { name: 'tautology', email: '\' OR 1=1--' },
    { name: 'comment out the password check', email: 'admin@juice-sh.op\'--' },
    { name: 'UNION SELECT a fake user', email: '\' UNION SELECT * FROM (SELECT 15 as \'id\', \'\' as \'username\', \'evil@juice-sh.op\' as \'email\', \'x\' as \'password\', \'admin\' as \'role\', \'\' as \'deluxeToken\', \'\' as \'lastLoginIp\', \'\' as \'profileImage\', \'\' as \'totpSecret\', 1 as \'isActive\', \'1999-08-16 14:14:41.644 +00:00\' as \'createdAt\', \'1999-08-16 14:33:41.930 +00:00\' as \'updatedAt\', null as \'deletedAt\')--' }
  ]

  for (const payload of payloads) {
    void it(`rejects SQL injection payload: ${payload.name}`, async () => {
      const res = await request(app)
        .post('/rest/user/login')
        .set(jsonHeader)
        .send({ email: payload.email, password: 'wrong-password' })

      assert.equal(res.status, 401, `SQL injection (${payload.name}) must not log anyone in`)
      assert.equal(res.body?.authentication, undefined, 'no token may be issued')
    })
  }
})

void describe('Security: authentication tokens must be verified (OWASP A07 Authentication Failures)', () => {
  void it('rejects an unsigned JWT (alg: none)', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url')
    const payload = Buffer.from(JSON.stringify({ data: { email: 'jim@juice-sh.op' }, iat: 1508639612, exp: 9999999999 })).toString('base64url')
    const forgedToken = `${header}.${payload}.`

    const res = await request(app)
      .get('/rest/basket/1')
      .set({ Authorization: 'Bearer ' + forgedToken })

    assert.equal(res.status, 401, 'a token without a valid signature must be rejected')
  })
})

void describe('Security: users can only access their own basket (OWASP A01 Broken Access Control)', () => {
  // Known issue, not fixed yet: kept visible as a TODO so it does not block the pipeline.
  // Tracked in the threat model ("IDOR on basket API"). Remove the todo option once fixed.
  void it('denies access to another user\'s basket (IDOR)', { todo: 'Known issue: IDOR on basket API (threat model), not fixed yet' }, async () => {
    const { token, bid } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
    const otherBasketId = bid === 1 ? 2 : 1

    const res = await request(app)
      .get(`/rest/basket/${otherBasketId}`)
      .set({ Authorization: 'Bearer ' + token })

    assert.ok([401, 403].includes(res.status),
      `user with basket ${bid} must not read basket ${otherBasketId} (got HTTP ${res.status})`)
  })
})

void describe('Security: errors must not leak internals (OWASP A10 Mishandling of Exceptional Conditions)', () => {
  // Known issue, not fixed yet: kept visible as a TODO so it does not block the pipeline.
  // Tracked in the threat model ("Error responses leak stack traces"). Remove the todo option once fixed.
  void it('does not return a stack trace on an unexpected API path', { todo: 'Known issue: stack traces in error responses (threat model), not fixed yet' }, async () => {
    const res = await request(app)
      .get('/api/ThisRouteDoesNotExist')
      .set({ Accept: 'application/json' })

    const body = res.text ?? ''
    assert.doesNotMatch(body, /\n\s+at\s+\S+/, 'response must not contain stack frames')
    assert.doesNotMatch(body, /node_modules|\.ts:\d+|\.js:\d+/, 'response must not reveal file paths')
  })
})
