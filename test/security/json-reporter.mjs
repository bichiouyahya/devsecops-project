/*
 * JSON reporter for the security unit tests (DevSecOps project, brief §6:
 * "rapports lisibles au format HTML et/ou JSON pour chaque type de scan").
 *
 * Node's built-in test runner ships spec, tap, dot and junit reporters, but no
 * JSON one. This custom reporter writes one JSON document: a summary
 * (total, pass, fail, todo, skip) and one entry per test.
 *
 * Usage: --test-reporter=./test/security/json-reporter.mjs
 *        --test-reporter-destination=security-tests.json
 */

export default async function * jsonReporter (source) {
  const tests = []

  for await (const event of source) {
    if (event.type !== 'test:pass' && event.type !== 'test:fail') continue
    const data = event.data
    // describe() blocks are reported as suites: keep only the tests themselves
    if (data.details?.type === 'suite') continue

    let status
    if (data.todo !== undefined) status = 'todo'
    else if (data.skip !== undefined) status = 'skip'
    else status = event.type === 'test:pass' ? 'pass' : 'fail'

    const error = data.details?.error
    tests.push({
      name: data.name,
      status,
      durationMs: data.details?.duration_ms,
      reason: typeof data.todo === 'string' ? data.todo : undefined,
      error: event.type === 'test:fail' ? String(error?.cause?.message ?? error?.message ?? '') : undefined
    })
  }

  const count = (s) => tests.filter((t) => t.status === s).length
  const report = {
    tool: 'node:test',
    suite: 'test/security/security.test.ts',
    generatedAt: new Date().toISOString(),
    summary: {
      total: tests.length,
      pass: count('pass'),
      fail: count('fail'),
      todo: count('todo'),
      skip: count('skip')
    },
    tests
  }
  yield JSON.stringify(report, null, 2) + '\n'
}
