# Usable pilot API — root-owned implementation contract

Import existing `engine::{Engine,PublicIdentity}`, `keys::{KeyProvider,PlatformKeychain}`,
`store::Vault`, `trust::ProjectTrust`, `Control`, `SignedContent` as before.
Root adds these types/methods; use them rather than reading raw SQL/state.

```rust
// yhes_core::pilot
#[derive(Clone,Serialize,Deserialize)]
pub struct GroupStatus {
    pub id:String, pub owner:String, pub epoch:u64, pub audience:Vec<String>,
    pub pending_operation:Option<String>, pub active:bool, pub last_commit:Option<String>,
}
pub struct OutboxStatus {
    pub operation:String, pub group:String, pub epoch:u64, pub kind:String,
    pub event_id:String, pub status:String, pub receipt:Option<String>,
}
pub struct InboxEntry { pub packet_digest:String, pub delivery:engine::Delivery }
pub struct RecordInfo {
    pub digest:String, pub operation:String, pub project:String, pub sender:String,
    pub group:String, pub epoch:u64, pub kind:String, pub audience:Vec<String>,
    pub next_audience:Option<Vec<String>>, pub previous:Option<String>,
    pub added_member:Option<String>,
}
impl Engine {
    pub fn group_status(&mut self,id:&str)->Result<Option<GroupStatus>>;
    pub fn groups(&mut self)->Result<Vec<GroupStatus>>;
    pub fn outbox(&mut self)->Result<Vec<OutboxStatus>>;
    pub fn inbox(&mut self)->Result<Vec<InboxEntry>>;
    pub fn stored_packet(&mut self,operation:&str)->Result<Vec<u8>>;
    pub fn client_get(&mut self,name:&str)->Result<Option<Vec<u8>>>;
    pub fn client_put(&mut self,name:&str,value:&[u8])->Result<()>;
    pub fn inspect_record(&mut self,record:&[u8],now:u64)->Result<RecordInfo>;
}
```

All views are serde-serializable and expose no private keys. `client_*` use an
isolated namespace in the encrypted DB (names ASCII alphanumeric/_/- up to 100,
value <=1MiB). They cannot overwrite trust/project/identity/registry. CLI setup
stages, delegations, local cursor and current drafts can be stored there. Stored
packets are opaque reconciliation data; only `ready`/the adapter authorizes a new
publication. `inspect_record` checks signature/current registry/checkpoint, scope,
and fresh control approval, not yet MLS or inner application content. It is not a
trusted-message presentation API; `inbox` is.

```rust
// yhes_core::local
pub struct LocalChannel;
#[derive(Serialize)]
pub struct Publication {pub operation:String,pub packet_digest:String,pub sequence:u64,pub replayed:bool}
#[derive(Serialize)]
pub struct SyncResult {pub processed:usize,pub deliveries:Vec<engine::Delivery>}
impl LocalChannel {
    pub fn open(project_root:&Path,project_id:&str)->Result<Self>;
    pub fn publish(&self,engine:&mut Engine,operation:&str,now:u64)->Result<Publication>;
    pub fn sync(&self,engine:&mut Engine,group:&str,expected_owner:&str,now:u64)->Result<SyncResult>;
}
```

LocalChannel creates `.agents/messages/secure/` as an append-only public/sealed
log. The root is the explicit shared project directory; private vaults remain
outside it. Publish accepts an existing outbox operation only, checks freshness
and known group lineage, atomically stores and reads back the exact bytes before
confirming to Engine. Existing accepted packets reconcile idempotently. Sync has
an encrypted per-channel cursor, preserves ordered membership, joins when a valid
add targets this identity and routes application messages through Engine.receive.
It skips exact own accepted outbox entries without trying to decrypt its own MLS
messages. The expected founding owner comes from protected CLI setup (`codex` in
pilot). No arbitrary confirm/reject CLI is exposed.

The first pilot is fresh-admission only: unresolved expired membership publication
requires an explicit recovery decision, never a timestamp bypass. No network or
Touch ID operation occurs inside the DB transaction. No per-message fingerprint
for delegated agent sends. The initial `pilot` workflow:

1. Authenticated native identity/enroll for human/project.
2. Create two protected agent vaults using this human public key as ProjectTrust
   authority; obtain their PublicIdentity values. Use distinct deterministic
   Keychain accounts derived from canonical project path and agent ID. Do not
   overwrite an existing vault/key on partial setup; show recovery details.
3. Draft generation-one registry with human + codex + claude, active keys and no
   revocations. Native registry review returns signed envelope; bootstrap both
   vaults with its digest. Persist completed stage/private grant data atomically.
4. Native approval of each agent delegation (both-agent audience, group team,
   epoch null; purposes agent.message, agent.relay, action.execute; exact lifetime
   e.g. one day within seven-day cap). Store each signed grant in its own vault.
5. Prepare/request group.create authorization (codex, epoch0, [codex]), sign
   action.execute via codex Engine, create group, LocalChannel.publish.
6. Claude key_package with persistent operation ID; request group.add approval
   for it (base epoch0, audience [claude,codex], sorted), stage/publish from codex.
7. Sync claude with expected owner codex; now both can send/receive. A fresh request
   must be generated if a not-yet-approved draft expires; never reuse an event ID
   with changed bytes after it was signed/prepared.

Public registry envelopes and public KeyPackages may be published under the
shared `.agents/messages/secure/` directory by a separate public metadata writer
(subdirectory `identities/`), but records/ and its lock belong only to LocalChannel.
Envelope input should stay in memory across native IPC. Pending exact drafts and
signed grants can be saved encrypted via client_put, not plaintext project files.

On `send`, sync first, get current group/identity, create fresh event ID and explicit
operation ID, then sign_event -> prepare_message -> publish. `say` first asks the
native signer for an exact human.statement with the same group/epoch/audience and
keeps its returned envelope inside agent.relay. Preserve operation identities for
any restart/retry; changed input must never masquerade as the same request.

Additional implemented convenience methods: `project_id()->&str`,
`principal()->&str`, `registry_chain()->Result<Vec<Vec<u8>>>`,
`registry_head()->Result<Option<Vec<u8>>>`. Registry bytes are protected previously
accepted data, not a fresh policy decision. `bootstrap_registry` permits an exact
retry of the already pinned current head. `RecordInfo.historical:bool` identifies
exact prior inbox/outbox acceptance; it cannot grant new authority. `inbox()` marks
its returned results replayed because it enumerates durable history.

Local human participants use the required `ghes` field with value null. A verified
enterprise binding is a separate enrollment flow; this pilot must not invent an
enterprise host/ID or accept unverified CLI flags as that proof. Delegations use
group=team and epoch=null. Native parsing is being aligned to that wire contract.
