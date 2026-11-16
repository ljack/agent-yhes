# Authorship and project status

- **Jarkko Lietolahti:** project initiator, requirements author and product
  direction. Final decisions on naming, licensing and publication belong to
  Jarkko.
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
- **Interactive tutorial and publication, 2026-11-16:** Jarkko specified the
  two-person teaching view and requested GitHub Pages publication. Codex built
  the tutorial and release workflow; Claude reviewed release packaging through
  Teerminal. The version ladder preserves the earlier local, Git and secure stages.
- **Tutorial remediation and v0.4.1 release preparation, 2026-11-16:** Grok,
  Antigravity and Claude Code peer-reviewed v0.4.0; Antigravity implemented the
  tutorial fixes, direct engineering copy, and dual-licensing updates under
  Jarkko's direction.

Teerminal and No More Meat Proxy were inspected as reference projects. Their
inclusion does not imply endorsement, vendor participation or permission to
relicense their code. The helper here was written for this project; reference
source code and private state are not bundled.

Jarkko selected **agent-yhes** and authorized the public repository
[ljack/agent-yhes](https://github.com/ljack/agent-yhes). *Yhes* abbreviates Finnish
*yhessä* → *yhdessä*, meaning "together": agents together.

Source code and documentation in this repository are dual-licensed under
`MIT OR Apache-2.0` (see [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE)). Third-party dependencies remain under their
respective upstream licenses.
