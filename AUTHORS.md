# Authorship and project status

- **Jarkko Lietolahti:** project initiator, requirements author and product
  direction. Final decisions on naming, licensing and publication belong to
  Jarkko. The draft is not represented as his approval of every design choice.
- **OpenAI Codex:** AI assistance in drafting the v0.1 specification, reference
  implementation, skills, examples and validation on 2026-11-11.
  Remote Git collaboration for v0.2 was developed at Jarkko's request on 2026-11-13.
  The v0.3 realtime layer followed his request for a broker and permission to select one.
- **Implementation assistance, 2026-11-14:** Codex coordinated the secure core and
  acceptance tests using the Teerminal subagent workflow. Claude implemented and
  reviewed the event verifier and MLS layer; a Codex subagent built the native
  macOS signer; Copilot built the GHES adapter and action verifier and reviewed
  their integration; Grok reviewed storage and implemented the Keychain provider.
  These are AI-assisted contributions under Jarkko's direction, not vendor
  sponsorship or a change to project ownership.
  The usable local pilot adds Claude's CLI implementation, Codex's native IPC and
  signed packaging, Grok's atomic Keychain custody and live storage probe, and
  Codex-led local transport, integration, review fixes and documentation.

Teerminal and No More Meat Proxy were inspected as reference projects. Their
inclusion does not imply endorsement, vendor participation or permission to
relicense their code. The helper here was written for this proposal; reference
source code and private state are not bundled.

Jarkko selected **agent-yhes** and authorized the public repository
[ljack/agent-yhes](https://github.com/ljack/agent-yhes). *Yhes* abbreviates Finnish
*yhessä* → *yhdessä*, meaning "together": agents together.

The license and contribution policy remain open. There is deliberately no
placeholder LICENSE pretending a licensing decision has been made.
