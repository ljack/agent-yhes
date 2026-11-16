// Disposable sender-key primitive test, not a complete Signal group application.
// Distribution packets are passed in memory as a trusted test fixture. In a
// product they must travel over authenticated, confidential pairwise sessions.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import * as S from '@signalapp/libsignal-client';

class Store extends S.SenderKeyStore {
  rows = new Map();
  key(sender, id) { return JSON.stringify([sender.name(), sender.deviceId(), id]); }
  async saveSenderKey(sender, id, record) {
    this.rows.set(this.key(sender, id), Buffer.from(record.serialize()));
  }
  async getSenderKey(sender, id) {
    const bytes = this.rows.get(this.key(sender, id));
    return bytes ? S.SenderKeyRecord.deserialize(bytes) : null;
  }
}

const sender = S.ProtocolAddress.new('human-label-only', 1);
const a = new Store(), b = new Store(), c = new Store(), d = new Store(), e = new Store();
const initial = randomUUID();
async function distribute(id, stores) {
  const packet = await S.SenderKeyDistributionMessage.create(sender, id, a);
  for (const store of stores) {
    await S.processSenderKeyDistributionMessage(sender,
      S.SenderKeyDistributionMessage.deserialize(packet.serialize()), store);
  }
}
async function encrypt(id, text) {
  return Buffer.from((await S.groupEncrypt(sender, id, a, Buffer.from(text))).serialize());
}
async function decrypt(store, bytes) {
  return Buffer.from(await S.groupDecrypt(sender, store, bytes)).toString();
}

await distribute(initial, [b, c]);
const old = await encrypt(initial, 'first-group-message');
assert.equal(await decrypt(b, old), 'first-group-message');
assert.equal(await decrypt(c, old), 'first-group-message');
await assert.rejects(() => decrypt(e, old));
await assert.rejects(() => decrypt(b, old));

const good = await encrypt(initial, 'integrity-check');
const bad = Buffer.from(good);
bad[bad.length - 1] ^= 1;
await assert.rejects(() => decrypt(b, bad));
assert.equal(await decrypt(b, good), 'integrity-check');
const early = await encrypt(initial, 'early');
const late = await encrypt(initial, 'late');
assert.equal(await decrypt(b, late), 'late');
assert.equal(await decrypt(b, early), 'early');

// A distribution made at the current chain position omits old message keys.
await distribute(initial, [d]);
await assert.rejects(() => decrypt(d, old));

// Merely changing an application's membership list does not update sender keys.
const withoutRotation = await encrypt(initial, 'membership-list-change-only');
assert.equal(await decrypt(c, withoutRotation), 'membership-list-change-only');

// The application rotates the distribution and delivers it only to B and D.
const rotated = randomUUID();
await distribute(rotated, [b, d]);
const future = await encrypt(rotated, 'after-removal-and-rekey');
await assert.rejects(() => decrypt(c, future));
assert.equal(await decrypt(b, future), 'after-removal-and-rekey');
assert.equal(await decrypt(d, future), 'after-removal-and-rekey');

const reloaded = new Store();
for (const [key, value] of b.rows) reloaded.rows.set(key, Buffer.from(value));
assert.equal(await decrypt(reloaded, await encrypt(rotated, 'after-reload')), 'after-reload');

console.log(JSON.stringify({implementation:'libsignal',version:'0.107.0',mode:'sender-key group primitive',
  checks:{multi_recipient:true,outsider_rejected:true,duplicate_rejected:true,
    tamper_rejected_without_poisoning:true,out_of_order:true,late_joiner_cannot_read_past:true,
    removed_member_cannot_read_future_after_app_rekey:true,remaining_members_continue:true,provider_state_reload:true},
  observations:{membership_list_alone_does_not_revoke_sender_key:true,application_must_rekey:true},
  identity:'trusted in-memory distribution fixture; no pairwise session, GHE or Touch ID test'}));
