# Yhes Signer component brief

The approved security plan and delegated implementation brief are the product
source for this component. No product/design interview was performed: this is
a bounded implementation subtask with explicitly owned paths.

The macOS human reviews an agent-prepared event, including its exact payload and
full audience, then intentionally approves that event with fresh Touch ID. The
root key stays in Secure Enclave. Software test keys cannot enter the executable.
Drafts and actual approvals must remain visibly distinct. The first component
fails closed on missing production identity, unknown event kinds and sessions.

Native AppKit is an implementation choice for this first macOS component.
Use system typography, native open/save dialogs, readable selectable payloads,
keyboard focus and text labels for every state. Large payloads and recipient
lists scroll. This is an operation screen; standard macOS behavior governs its
appearance. No brand, onboarding, remote trust UI or release certification is
implied. Live UI/hardware acceptance remains outstanding under the task's
pure-test-only boundary.

The approved followup adds a lower-prompt fixed batch of exact human statements
and an explicit registry-signing mode. The batch is fully reviewed before one
fresh authentication context and cannot accept later data. Registry approval
names the whole trust change and requires independently pinned authority keys.
Neither feature grants a timed signing session or claims remote hardware attestation.

The approved first usable local pilot adds authenticated CLI enrollment and review
requests. Preserve the native AppKit appearance. Operate-mode first-run UI explains
how to start setup, shows signing/provisioning failures with next actions, and
returns approvals directly to the waiting CLI. Human statements show readable
exact source text and full scope before a fresh Touch ID action. Raw JSON remains
available through disclosure. Local humans may have no enterprise identity claim.
No design interview is needed for this bounded integration; no real enrollment
or biometric approval is automated in visual or software tests.
