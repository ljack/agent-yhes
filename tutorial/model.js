(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.YhesTutorial = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';
  const bootstrap = 'Use https://github.com/ljack/agent-yhes (or your local agent-yhes checkout). Read BOOTSTRAP.md and bootstrap this workspace for the two-user simulation.';
  const names = { alice: 'Alice', bob: 'Bob' };
  const other = side => side === 'alice' ? 'bob' : 'alice';
  const node = (side, kind) => `${side}-${kind}`;
  const entry = (side, text, kind = 'result') => ({ side, text, kind });
  const frame = (title, text, why, route, extra = {}) => ({ title, text, why, route, entries: [], ...extra });
  const objects = {
    human: { title: 'Human', job: 'Sets the goal. Approves authority.', detail: 'The person chooses the task and reviews protected changes. A typed instruction to an agent is not automatically a human-signed statement.', why: 'People retain control of identities, permissions and confidential audiences.' },
    terminal: { title: 'Terminal', job: 'The visible conversation and commands.', detail: 'A terminal is an interface. It displays the harness and CLI output; it is not the agent identity or the message transport.', why: 'The same protocol can be used from different terminal and harness tools.' },
    harness: { title: 'Harness', job: 'Hosts the agent’s working loop.', detail: 'Codex, Claude, Antigravity, Grok and Copilot are examples. The harness supplies context, tools and its own approval controls. An active adapter can read Yhes messages.', why: 'Collaboration belongs to the project, so it can cross harness boundaries.' },
    agent: { title: 'Agent', job: 'Acts within delegated permissions.', detail: 'An enrolled agent profile has its own signing key. The harness drives its work and invokes the Yhes CLI. A signature identifies the enrolled key, not an attested model executable.', why: 'You can tell which agent authored a message without borrowing a human identity.' },
    llm: { title: 'LLM', job: 'Helps reason and draft.', detail: 'The model may help the agent decide what to do or compose a reply. Direct CLI operations can skip this step. It does not possess the Yhes signing key or perform transport verification.', why: 'Reasoning, identity and permission are separate. Verified plaintext may enter model context if the harness sends it there.' },
    biometric: { title: 'Biometrics', job: 'Permits a local human signature.', detail: 'Touch ID permits Yhes Signer to use a Secure Enclave key for the exact reviewed content. Biometric data never leaves the device; public-key fingerprints are separate trust identifiers shared between peers.', why: 'A human approval should bind specific words or authority—not grant an agent an open signing session.' },
    crypto: { title: 'Signing & encryption', job: 'Local tools protect and verify content.', detail: 'Yhes signs the event under the correct identity, encrypts application messages for the MLS group, and persists its outbox. Recipients decrypt and verify locally before exposing accepted text.', why: 'Signatures establish authorship. Encryption limits who can read the content. Neither turns prose into permission to execute it.' },
    git: { title: 'Git client', job: 'Publishes and fetches exact records.', detail: 'The local Git tool uses a separate cache and a dedicated coordination branch. It reads back the accepted record before confirming publication. The source worktree stays separate.', why: 'Two clients can reconcile the same durable history, including after an interrupted push.' },
    repository: { title: 'Shared Git repository', job: 'The durable coordination record.', detail: 'The repository holds signed public registries, enrollment requests and membership records, plus encrypted application packets. Its author strings and mere possession of a file do not establish protocol authority.', why: 'Git supplies shared ordering and recovery; independently pinned keys and verified signatures supply trust.' },
    jetstream: { title: 'NATS JetStream', job: 'Wakes an active receiver.', detail: 'After Git confirms publication, the sender can publish the exact ciphertext to JetStream. A running listener wakes and reconciles Git before accepting it. A broker ACK is transport progress, not proof that the other agent handled the message.', why: 'Receivers can react without waiting for the next poll. An idle model still needs its harness to start or resume it.' }
  };

  function connectFrames(side = 'alice') {
    const n = kind => node(side, kind), p = kind => node(other(side), kind);
    return [
      frame('Two people start their own agents', 'Alice and Bob work in separate directories. Each controls their own agent.', 'A workspace is a working context. In the same-Mac lab, separate disposable profiles stand in for two people.', [n('human'), n('terminal'), n('harness'), n('agent')], {
        entries: [entry('alice', '$ bootstrap', 'command'), entry('bob', '$ bootstrap', 'command')], active: [p('terminal'), p('agent')], packet: 'Two independent identities', status: 'Not joined yet'
      }),
      frame('Alice establishes the project', 'Alice approves the first registry locally on her device. Her authority public key and registry digest become the trust anchors.', 'Alice’s biometric check stays local on her Mac to unlock signing. Separately, Bob verifies Alice’s authority public-key fingerprint and exact initial registry digest out of band—a repository cannot choose its own trusted authority.', ['alice-biometric', 'alice-crypto', 'alice-git', 'repository'], {
        entries: [entry('alice', 'Initial registry published.'), entry('bob', 'Checking founder key + registry digest…')], packet: 'Public keys + signed registry', status: 'Founder established'
      }),
      frame('Bob requests a place in the team', 'Bob publishes a signed proposal for his human and agent identities. It is still awaiting admission.', 'Creating an identity, having Git access and submitting a request are different from being admitted.', ['bob-biometric', 'bob-crypto', 'bob-git', 'repository'], {
        entries: [entry('bob', 'Enrollment request published. Awaiting Alice.')], packet: 'Signed enrollment request', status: 'Request submitted'
      }),
      frame('Alice reviews who is joining', 'After checking Bob’s public-key fingerprint, Alice approves the next registry with Bob’s exact keys.', 'The founder approves the authority change. Bob’s self-signed proposal supplies evidence; it cannot promote itself to membership.', ['repository', 'alice-git', 'alice-agent', 'alice-biometric', 'alice-crypto', 'alice-git', 'repository'], {
        entries: [entry('alice', 'Bob’s identity admitted to the registry.')], packet: 'Approved registry update', status: 'Identity admitted'
      }),
      frame('Permissions and the encrypted group', 'Bob supplies his KeyPackage. Each person approves their own agent’s permissions; Alice approves group creation and adding Bob.', 'The add approval binds Bob’s exact KeyPackage. In the current pilot, the initial membership exchange must complete within its five-minute approval window.', ['bob-crypto', 'bob-git', 'repository', 'alice-git', 'alice-crypto', 'alice-git', 'repository'], {
        entries: [entry('bob', 'KeyPackage published; waiting for invitation.'), entry('alice', 'Approved group creation + Bob’s addition.')], packet: 'Approved membership + invitation', status: 'Joining'
      }),
      frame('Both sides verify the same team', 'Bob verifies the invitation and joins. Both clients now agree on membership and epoch.', 'Alice’s own ready result is not proof Bob has joined. Each participant verifies its local state independently.', ['repository', 'bob-git', 'bob-crypto', 'bob-agent'], {
        entries: [entry('alice', 'Ready · team · epoch 1'), entry('bob', 'Ready · team · epoch 1')], active: ['alice-agent', 'bob-agent'], packet: 'Alice + Bob · epoch 1', status: 'Both ready'
      })
    ];
  }

  function messageFrames(side, text, offline) {
    const peer = other(side), person = names[side], recipient = names[peer];
    const n = kind => node(side, kind), p = kind => node(peer, kind);
    return [
      frame(`${person} gives the task`, 'The terminal brings the request into the harness. The agent works within its existing delegation.', 'Delegation lets an agent send routine coordination messages under its own enrolled key without prompting the human on every turn.', [n('human'), n('terminal'), n('harness'), n('agent')], {
        entries: [entry(side, `$ send ${JSON.stringify(text)}`, 'command')], packet: 'Task → agent', status: 'Draft'
      }),
      frame('Reasoning is separate from identity', 'The harness may consult an LLM to help the agent draft its message.', 'The model does not hold the signing key. A direct CLI send can skip this reasoning step entirely.', [n('agent'), n('llm'), n('agent')], {
        entries: [entry(side, 'Draft ready. Sending as my agent.')], packet: text, status: 'Agent-authored draft', optional: true
      }),
      frame('Sign, encrypt, save locally', 'Yhes signs as the agent, encrypts for the group and saves the exact outgoing packet before sending it.', 'Agent signatures and group encryption serve different purposes. Routine delegated agent messages need no Touch ID.', [n('agent'), n('crypto')], {
        entries: [entry(side, 'Signed as agent · encrypted · outbox saved.')], packet: 'Sealed application packet', sealed: true, status: 'Protected locally'
      }),
      frame('Git confirms the durable record', 'The local Git client publishes the packet and reads it back from the shared branch.', 'A push acknowledgment alone is not enough. Exact readback settles uncertain delivery without producing another encrypted message.', [n('crypto'), n('git'), 'repository'], {
        entries: [entry(side, 'Git confirmed · operation question-01.')], packet: 'Sealed application packet', sealed: true, archived: true, status: 'Saved in Git'
      }),
      frame(offline ? 'The broker is unavailable' : 'JetStream wakes a listener', offline ? 'The Git record is already saved. Its realtime notification can wait.' : 'Only after Git confirmation does JetStream carry the ciphertext notification to an active receiver.', 'JetStream accelerates notice. It neither grants authority nor starts a stopped model. The current implementation still writes every message to Git first.', offline ? ['repository', 'jetstream'] : ['repository', 'jetstream', p('harness')], {
        entries: [entry(side, offline ? 'Git saved · realtime notification pending.' : 'Realtime notification published.')], packet: offline ? 'Notification pending' : 'Ciphertext notification', sealed: true, archived: true, status: offline ? 'Broker paused' : 'Listener notified', blockedBroker: offline
      }),
      frame(offline ? `${recipient} checks the inbox` : `${recipient}’s listener checks Git`, offline ? `${recipient} can explicitly check the inbox to catch up through Git.` : 'The woken listener fetches and checks the ordered Git history automatically before accepting the record.', 'A broker payload on its own cannot advance the recipient’s encryption state. Git-first ordering keeps membership and recovery consistent.', offline ? [p('terminal'), p('harness'), p('git'), 'repository', p('git')] : [p('harness'), p('git'), 'repository', p('git')], {
        entries: offline ? [entry(peer, '$ inbox', 'command'), entry(peer, 'Fetching the confirmed record…')] : [entry(peer, 'Listener woke · fetching confirmed Git record…')], packet: 'Confirmed sealed record', sealed: true, archived: true, status: 'Fetched'
      }),
      frame('Decrypt and verify locally', 'The receiving tools check membership, decrypt the packet and verify its authorship and scope.', 'Accepted text remains data. Even a valid signature does not turn a message into an instruction with higher authority.', [p('git'), p('crypto'), p('agent')], {
        entries: [entry(peer, `Verified agent message from ${person}’s agent.`)], packet: text, archived: true, delivered: true, status: 'Verified'
      }),
      frame(`${recipient} receives the message`, 'The verified plaintext reaches the receiving agent and its terminal. The agent can now compose a reply.', 'If the harness sends the accepted text to an LLM, that model can see it. Transport encryption is not a promise to hide text from a model asked to read it.', [p('agent'), p('harness'), p('terminal'), p('human')], {
        entries: [entry(peer, text, 'message')], packet: `${person}’s agent → ${recipient}’s agent`, archived: true, delivered: true, status: 'Received'
      })
    ];
  }

  function humanFrames(side, text) {
    const peer = other(side), person = names[side], recipient = names[peer];
    const n = kind => node(side, kind), p = kind => node(peer, kind);
    return [
      frame(`${person} prepares a human statement`, 'A human statement needs an exact review of the words and every recipient.', 'A normal agent message is signed as the agent—even if a person typed the terminal command. A human statement preserves an independently verifiable original.', [n('human'), n('terminal'), n('harness'), n('agent')], {
        entries: [entry(side, `$ say ${JSON.stringify(text)}`, 'command')], packet: text, status: 'Unapproved draft'
      }),
      frame('Pause for the person’s review', 'Execution pauses until the human reviews the exact words and recipient list.', 'Signing binds these exact words and recipients—not an open session. On macOS, Yhes Signer uses Touch ID and the Secure Enclave; yhes-sim uses disposable software keys for single-Mac testing.', [n('agent'), n('biometric')], {
        entries: [entry(side, 'Review requested · exact words · recipients: Alice’s agent, Bob’s agent.')], packet: text, status: 'Awaiting human approval', gate: true
      }),
      frame('The human key signs on the device', 'Touch ID unlocks the local human key to sign the reviewed statement.', 'Biometric fingerprint data never goes to the model, Git or the broker. A public-key fingerprint is different: it is deliberately shared to verify identity.', [n('human'), n('biometric'), n('crypto')], {
        entries: [entry(side, 'Approved · human statement signed.')], packet: `Original author: ${person}`, human: true, status: 'Human original signed'
      }),
      frame('The agent carries the unchanged original', 'The agent adds its own signed relay and encrypts the result for the group.', 'The outer message is still agent-authored. It contains the original human signature and exact words; a paraphrase would remain agent-authored text.', [n('crypto'), n('agent'), n('crypto')], {
        entries: [entry(side, 'Human original preserved inside agent relay.')], packet: 'Human signature inside sealed relay', human: true, sealed: true, status: 'Relay encrypted'
      }),
      frame('Publish, then notify', 'Git confirms the encrypted relay before JetStream notifies the active receiver.', 'The recipient must admit a new human statement before its receive-before deadline—currently at most 30 minutes from creation. Accepted history remains readable afterward.', [n('crypto'), n('git'), 'repository', 'jetstream', p('harness')], {
        entries: [entry(side, 'Relay saved in Git · notification sent.')], packet: 'Sealed relay', human: true, sealed: true, archived: true, status: 'Published'
      }),
      frame(`${recipient} verifies both authors`, 'The receiver checks Git, decrypts locally and verifies the human original separately from the agent relay.', 'A valid human signature establishes whose reviewed statement this is. The receiving agent must still interpret it within the task and permissions already granted.', [p('git'), 'repository', p('git'), p('crypto'), p('agent')], {
        entries: [entry(peer, `Verified human original: ${person}.`), entry(peer, `Relay author: ${person}’s agent.`)], packet: text, human: true, archived: true, delivered: true, status: 'Both signatures verified'
      }),
      frame('The distinction survives the journey', 'The recipient sees the exact human words and the agent that carried them.', 'Human authorship and agent relay stay separate end to end. Get started links the runnable yhes-sim lab and native pilot.', [p('agent'), p('harness'), p('terminal'), p('human')], {
        entries: [entry(peer, text, 'human')], packet: `Human: ${person} · relay: ${person}’s agent`, human: true, archived: true, delivered: true, status: 'Received with provenance'
      })
    ];
  }

  function recoveryFrames(side = 'bob', text = 'Please check retries.') {
    const receiver = side, sender = other(side);
    const r = kind => node(receiver, kind), s = kind => node(sender, kind);
    const recName = names[receiver], sendName = names[sender];
    return [
      frame('A saved message, a missed notification', `${sendName}’s encrypted message has reached Git, but the broker is unavailable.`, 'Publication and notification are separate outcomes. A broker connection failure does not erase a confirmed Git record.', [s('crypto'), s('git'), 'repository', 'jetstream'], {
        entries: [entry(sender, `$ send ${JSON.stringify(text)}`, 'command'), entry(sender, 'Git confirmed · realtime pending.')], packet: 'Saved packet · operation note-01', archived: true, sealed: true, blockedBroker: true, status: 'Notification pending'
      }),
      frame(`${recName} catches up through Git`, `${recName} explicitly runs inbox and fetches the durable record from Git.`, 'The CLI does not need a broker notification to discover records. An unavailable listener may need restarting; the inbox is the explicit fallback.', [r('terminal'), r('harness'), r('git'), 'repository', r('git')], {
        entries: [entry(receiver, '$ inbox', 'command'), entry(receiver, 'Found one unseen Git record.')], packet: 'Confirmed packet', archived: true, sealed: true, blockedBroker: true, status: 'Git catch-up'
      }),
      frame('The usual verification still applies', `${recName} decrypts and verifies the saved packet locally, then records its accepted message.`, 'Recovery is not a weaker verification path. Membership, signatures, deadlines and replay checks still apply.', [r('git'), r('crypto'), r('agent'), r('harness'), r('terminal')], {
        entries: [entry(receiver, `Verified · ${text}`, 'message')], packet: 'Accepted once', archived: true, delivered: true, blockedBroker: true, status: 'Message received'
      }),
      frame('Retry the pending notification', `When the broker returns, ${sendName}’s client can flush pending notifications for Git-confirmed messages.`, 'Flush does not invent acceptance for an unarchived operation. If Git confirmation is false, preserve the operation ID and diagnose the error.', ['repository', 'jetstream', r('harness')], {
        entries: [entry(sender, 'Broker back · pending notice flushed.')], packet: 'Same packet · same operation', archived: true, delivered: true, status: 'Broker available'
      }),
      frame('One event, even after a retry', 'An identical send retry reuses the stored event and ciphertext. Reopening retrieves accepted history.', 'Reuse an operation ID only for identical input. Changed input conflicts. A historical read reports earlier acceptance, not renewed authority.', [s('git'), 'repository', r('git'), r('crypto'), r('agent'), r('terminal')], {
        entries: [entry(sender, 'Replay: note-01 · no new publication.'), entry(receiver, 'History: 1 event · already read.')], packet: '1 accepted event', archived: true, delivered: true, status: 'No duplicate'
      })
    ];
  }

  const chapters = [
    { id: 'connect', title: 'Connect', description: 'Who gets to join?', command: 'bootstrap' },
    { id: 'message', title: 'Message', description: 'Follow an agent message.', command: 'send "Can you review the retry logic?"' },
    { id: 'human', title: 'Human approval', description: 'Keep the human original.', command: 'say "I approve this direction."' },
    { id: 'recovery', title: 'Catch up', description: 'A missed wake-up is recoverable.', command: 'inbox' }
  ];
  function defaultText(chapter, side) {
    if (chapter === 'human') return side === 'bob' ? 'I agree with this proposal.' : 'I approve this direction.';
    if (chapter === 'recovery') return 'Please check retries.';
    return side === 'bob' ? 'I checked the retry behavior.' : 'Can you review the retry logic?';
  }
  function create(chapter = 'connect', side, text = '', offline = false) {
    if (side === undefined) side = chapter === 'recovery' ? 'bob' : 'alice';
    if (!chapters.some(c => c.id === chapter) || !names[side]) throw new Error('Unknown tutorial state');
    const message = String(text || defaultText(chapter, side)).slice(0, 240);
    return { chapter, side, text: message, offline: chapter === 'message' ? !!offline : false, index: 0, approved: false };
  }
  function frames(state) {
    if (state.chapter === 'connect') return connectFrames(state.side);
    if (state.chapter === 'human') return humanFrames(state.side, state.text);
    if (state.chapter === 'recovery') return recoveryFrames(state.side, state.text);
    return messageFrames(state.side, state.text, state.offline);
  }
  function current(state) { return frames(state)[state.index]; }
  function needsApproval(state) { return !!current(state).gate && !state.approved; }
  function next(state) {
    if (needsApproval(state)) return { ...state };
    return { ...state, index: Math.min(state.index + 1, frames(state).length - 1) };
  }
  function previous(state) {
    const index = Math.max(0, state.index - 1);
    const gate = frames(state).findIndex(f => f.gate);
    return { ...state, index, approved: gate >= 0 && index <= gate ? false : state.approved };
  }
  function approve(state) { return needsApproval(state) ? next({ ...state, approved: true }) : { ...state }; }
  function history(state, side) {
    return frames(state).slice(0, state.index + 1).flatMap(f => f.entries).filter(e => e.side === side);
  }
  function commands(state) {
    const peer = other(state.side);
    if (state.chapter === 'connect') return { alice: 'bootstrap', bob: 'bootstrap' };
    if (state.chapter === 'recovery') return { [state.side]: 'inbox', [peer]: `send ${JSON.stringify(state.text)}` };
    const verb = state.chapter === 'human' ? 'say' : 'send';
    return { [state.side]: `${verb} ${JSON.stringify(state.text)}`, [peer]: `${verb} ${JSON.stringify(defaultText(state.chapter, peer))}` };
  }
  function parse(command, side) {
    const input = String(command).trim();
    if (/^listen(?:\s|$)/i.test(input)) return { error: 'Listener wake-up is shown in Message. Use send "Hello" or inbox here (CLI: yhes-sim listen / bin/yhes team-listen).' };
    if (/^flush(?:\s|$)/i.test(input)) return { error: 'Notification retry is shown in Catch up step 4. Use inbox here (CLI: bin/yhes team-flush).' };
    if (/^connect(?:\s|$)/i.test(input)) return { error: 'Use bootstrap to step through Connect (CLI: yhes-sim bootstrap / bin/yhes team-connect).' };
    const match = /^(bootstrap|send|say|inbox|help)(?:\s+([\s\S]*))?$/i.exec(input);
    if (!match) return { error: 'Try bootstrap, send "a message", say "your words", inbox, or help.' };
    const verb = match[1].toLowerCase();
    const rawArg = (match[2] || '').trim();
    if ((verb === 'help' || verb === 'bootstrap' || verb === 'inbox') && rawArg) {
      return { error: `"${verb}" takes no arguments here.` };
    }
    if (verb === 'help') return { help: true };
    let text = rawArg;
    if (text.startsWith('"')) {
      try { text = JSON.parse(text); } catch { return { error: 'Close the quoted message, for example: send "Hello Bob".' }; }
    }
    if (typeof text !== 'string' || text.length > 240) return { error: 'Keep messages under 240 characters.' };
    if ((verb === 'send' || verb === 'say') && !text.trim()) return { error: `Add words after ${verb}, for example: ${verb} "Hello".` };
    const chapter = verb === 'bootstrap' ? 'connect' : verb === 'send' ? 'message' : verb === 'say' ? 'human' : 'recovery';
    return { state: create(chapter, side, text) };
  }
  return { bootstrap, names, objects, chapters, create, frames, current, needsApproval, next, previous, approve, history, commands, parse };
});
