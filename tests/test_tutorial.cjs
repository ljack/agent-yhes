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
test('catch up inbox, prefills and replay respect the chosen actor and custom text', () => {
  const aliceCatchup = M.parse('inbox', 'alice').state;
  assert.equal(aliceCatchup.chapter, 'recovery');
  assert.equal(aliceCatchup.side, 'alice');
  assert.deepEqual(M.commands(aliceCatchup), { alice: 'inbox', bob: 'send "Please check retries."' });
  const endAlice = { ...aliceCatchup, index: M.frames(aliceCatchup).length - 1 };
  assert(M.history(endAlice, 'alice').some(e => e.kind === 'command' && e.text === '$ inbox'));
  assert(M.history(endAlice, 'bob').some(e => e.kind === 'command' && e.text === '$ send "Please check retries."'));
  assert(M.history(endAlice, 'alice').every(e => !e.text.startsWith('$ send')));

  const defaultRecovery = M.create('recovery');
  assert.equal(defaultRecovery.side, 'bob');
  assert.deepEqual(M.commands(defaultRecovery), { alice: 'send "Please check retries."', bob: 'inbox' });
  const endDefault = { ...defaultRecovery, index: M.frames(defaultRecovery).length - 1 };
  assert(M.history(endDefault, 'bob').some(e => e.kind === 'command' && e.text === '$ inbox'));
  assert(M.history(endDefault, 'alice').some(e => e.kind === 'command' && e.text === '$ send "Please check retries."'));

  const customBobSend = M.parse('send "Custom Bob reply"', 'bob').state;
  assert.equal(M.commands(customBobSend).bob, 'send "Custom Bob reply"');
  const customAliceSay = M.parse('say "Exact Alice words"', 'alice').state;
  assert.equal(M.commands(customAliceSay).alice, 'say "Exact Alice words"');
});
test('online listener message flow avoids manual inbox command while offline uses inbox', () => {
  const online = M.create('message', 'alice', 'Hi', false);
  const onlineEnd = { ...online, index: M.frames(online).length - 1 };
  assert(M.history(onlineEnd, 'bob').every(e => e.text !== '$ inbox'));
  assert(M.history(onlineEnd, 'bob').some(e => e.text.includes('Listener woke')));

  const offline = M.create('message', 'alice', 'Hi', true);
  const offlineEnd = { ...offline, index: M.frames(offline).length - 1 };
  assert(M.history(offlineEnd, 'bob').some(e => e.kind === 'command' && e.text === '$ inbox'));
});
test('non-demo shortcuts and trailing arguments are rejected clearly while supported verbs work on both sides', () => {
  for (const bad of ['listen', 'flush', 'connect', 'inbox now', 'bootstrap extra', 'help me']) {
    for (const side of ['alice', 'bob']) {
      assert(M.parse(bad, side).error, `expected error for ${bad} on ${side}`);
    }
  }
  for (const side of ['alice', 'bob']) {
    assert.equal(M.parse('bootstrap', side).state.chapter, 'connect');
    assert.equal(M.parse('send "Ping"', side).state.chapter, 'message');
    assert.equal(M.parse('say "Confirm"', side).state.chapter, 'human');
    assert.equal(M.parse('inbox', side).state.chapter, 'recovery');
    assert.equal(M.parse('help', side).help, true);
  }
});
test('broker offline flag stays scoped to Message and key copy distinguishes fingerprint and recipients', () => {
  assert.equal(M.create('human', 'alice', 'Hi', true).offline, false);
  assert.equal(M.create('connect', 'alice', '', true).offline, false);
  assert(M.frames(M.create('connect'))[1].why.includes('public-key fingerprint'));
  assert(M.frames(M.create('human', 'alice', 'Hi'))[1].entries.some(e => e.text.includes('Alice’s agent, Bob’s agent')));
});
test('tutorial UI copy omits defensive guarding boilerplate', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const root = path.resolve(__dirname, '../tutorial');
  const combined = ['index.html', 'model.js', 'app.js'].map(f => fs.readFileSync(path.join(root, f), 'utf8')).join('\n');
  for (const phrase of [
    'no commands run here',
    'cannot use Touch ID',
    'no shell, model',
    'Browser illustration',
    'Visual demo',
    'in example',
    'Approve example',
    'Cancel example',
  ]) {
    assert(!combined.includes(phrase), `unexpected guarding phrase: ${phrase}`);
  }
});
