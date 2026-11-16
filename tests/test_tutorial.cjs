const test = require('node:test');
const assert = require('node:assert/strict');
const M = require('../tutorial/model.js');

test('human approval cannot be crossed by Next or playback alone', () => {
  let state = M.create('human', 'alice', 'These exact words.');
  state = M.next(state);
  assert.equal(M.needsApproval(state), true);
  for (let n = 0; n < 10; n++) state = M.next(state);
  assert.equal(state.index, 1);
  state = M.approve(state);
  assert.equal(state.index, 2);
  assert.equal(state.text, 'These exact words.');
  state = M.previous(state);
  assert.equal(M.needsApproval(state), true);
});
test('editing a human statement starts a fresh illustrative review', () => {
  const old = M.approve(M.next(M.create('human', 'alice', 'First.')));
  assert.equal(old.approved, true);
  const fresh = M.parse('say "Changed."', 'alice').state;
  assert.equal(fresh.approved, false);
  assert.equal(fresh.index, 0);
  assert.equal(fresh.text, 'Changed.');
});
test('Git confirmation precedes broker notification and recipient plaintext', () => {
  for (const side of ['alice', 'bob']) {
    const frames = M.frames(M.create('message', side, 'Check this.'));
    const stored = frames.findIndex(f => f.archived);
    const notice = frames.findIndex(f => f.route.includes('jetstream'));
    const received = frames.findIndex(f => f.delivered);
    assert(stored < notice && notice < received);
    assert(frames.slice(0, received).every(f => !f.entries.some(e => e.kind === 'message')));
  }
});
test('broker outage leaves the Git path and a verified endpoint', () => {
  const frames = M.frames(M.create('message', 'alice', 'Still saved.', true));
  const pending = frames.find(f => f.blockedBroker);
  assert.equal(pending.archived, true);
  assert.equal(frames.at(-1).delivered, true);
  assert(frames.at(-1).entries.some(e => e.side === 'bob' && e.text === 'Still saved.'));
});
test('reply direction and simulated human provenance are kept distinct', () => {
  let reply = M.create('message', 'bob', 'Reply from Bob.');
  reply.index = M.frames(reply).length - 1;
  assert(M.history(reply, 'alice').some(e => e.text === 'Reply from Bob.'));
  let human = M.create('human', 'bob', 'Bob’s exact words.');
  human.index = M.frames(human).length - 1;
  const received = M.history(human, 'alice');
  assert(received.some(e => e.text === 'Verified human original: Bob.'));
  assert(received.some(e => e.text === 'Relay author: Bob’s agent.'));
  assert(received.some(e => e.kind === 'human' && e.text === 'Bob’s exact words.'));
});
test('navigation is bounded and replay creates no accumulated messages', () => {
  let state = M.create('message');
  assert.equal(M.previous(state).index, 0);
  for (let n = 0; n < 50; n++) state = M.next(state);
  assert.equal(state.index, M.frames(state).length - 1);
  assert.equal(M.history(state, 'bob').filter(e => e.kind === 'message').length, 1);
  assert.equal(M.history(M.create('message'), 'bob').length, 0);
});
test('example command parser treats text as data and rejects unsupported commands', () => {
  assert(M.parse('rm -rf anything', 'alice').error);
  assert(M.parse('send', 'alice').error);
  assert(M.parse('say "unclosed', 'alice').error);
  assert(M.parse(`send "${'a'.repeat(241)}"`, 'alice').error);
  assert.equal(M.parse('send "<img src=x onerror=alert(1)>"', 'alice').state.text, '<img src=x onerror=alert(1)>');
  assert.equal(M.parse('help', 'bob').help, true);
});
test('all required actors are described and scenario routes only use known objects', () => {
  const ids = new Set(['repository', 'jetstream']);
  for (const side of ['alice', 'bob']) for (const type of ['human', 'terminal', 'harness', 'agent', 'llm', 'biometric', 'crypto', 'git']) ids.add(`${side}-${type}`);
  for (const chapter of M.chapters) for (const side of ['alice', 'bob']) {
    for (const frame of M.frames(M.create(chapter.id, side))) {
      assert(frame.title && frame.text && frame.why);
      frame.route.forEach(id => assert(ids.has(id), id));
    }
  }
  assert.equal(Object.keys(M.objects).length, 10);
});
