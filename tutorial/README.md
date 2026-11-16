# See how agent-yhes works

An interactive walkthrough with Alice and Bob, their own terminals and agents,
and shared Git and JetStream services. Click an object to see its job, or open
“Why this step?” for a short explanation.

[Open the published tutorial](https://ljack.github.io/agent-yhes/).

From the repository root, run:

```sh
python3 tools/tutorial_server.py
```

Open the local URL printed by the command. The server chooses an available port
and serves the tutorial and its linked guides. Stop it with Ctrl+C. You can also
open `tutorial/index.html` directly; the local server makes guide navigation and
copying the setup prompt more convenient.

## Try it

1. **Connect:** use Next step or Play flow to follow identity setup, the shared
   registry and the two participants joining.
2. **Message:** follow an agent message through signing, encryption, Git
   confirmation, a JetStream notice and verification by the recipient. Try Pause
   broker in example to see the Git fallback.
3. **Human approval:** review the example's exact words and recipients. Approve
   example continues the illustration; Cancel example leaves it unsigned.
4. **Catch up:** see how an active listener and a returning agent use the saved
   history. This flow does not start a dormant model.
5. **Get started:** choose the same-Mac simulation or the real two-person pilot.
   Follow the linked repository instructions in your own terminal.

Both example terminals accept editable shortcuts, including `send "your text"`,
`say "your text"`, `bootstrap`, `inbox` and `help`. Run animates the matching
explanation. These are tutorial shortcuts; the linked guides contain the real
CLI commands. Back and Replay let you inspect the same flow again.

The page runs entirely in the browser. It illustrates signing, encryption and
biometric approval; it does not run shell commands, call a model, create keys or
send messages. The real same-Mac simulation uses disposable identities, while
the real human-device pilot uses the native signer and Touch ID.

## Check or change the tutorial

`model.js` contains the stories and command parser; `app.js` renders the state
and animations. `index.html` and `style.css` define the actors and responsive
layout. There are no packages to install or external assets to fetch.

```sh
node --test tests/test_tutorial.cjs
```

The tests check approval boundaries, message ordering, fallback delivery,
direction, replay and input handling. The [QA record](../.impeccable/review/qa.md)
describes the browser checks. For the actual implementation's test results, read
[Validation](../docs/VALIDATION.md).

## Publish or preview the Pages build

```sh
python3 tools/build_site.py
python3 -m http.server 8000 --bind 127.0.0.1 --directory dist/site
```

Open `http://127.0.0.1:8000/`. The build copies four tutorial assets, adds version
metadata, and points guide links to rendered files on GitHub. It does not copy
the checkout or runtime state. Asset URLs also work under `/agent-yhes/`.

The `Publish tutorial` GitHub Actions workflow tests, builds and deploys changes
from `main`. It can also be run manually from Actions. Pages is configured to use
GitHub Actions; no separate `gh-pages` source branch is needed. The deployed
`build.json` identifies the source commit and release version, and guide links
use that same commit. To inspect an earlier version, check out its tag locally.

The workflow follows GitHub's [custom Pages workflow documentation](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages).
