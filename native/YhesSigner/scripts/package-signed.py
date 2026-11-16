#!/usr/bin/env python3
"""Package locally provisioned app + engine. Never export keys or upload artifacts."""
from pathlib import Path
import datetime
import hashlib
import os
import plistlib
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
REPO = ROOT.parent.parent
TEAM = '25C9H9N953'

if sys.argv[1:] not in ([], ['--check-profiles']):
    sys.exit('Usage: package-signed.py [--check-profiles]')

def permits_identifier(value, exact):
    # Xcode may issue its Apple-managed team wildcard for local macOS apps.
    # It authorizes these dedicated signed IDs; unrelated product profiles do not.
    return value in (exact, TEAM + '.*')

def profile(name, bundle, group):
    path = ROOT / 'build/Provisioning/Products' / (name + '.app') / 'Contents/embedded.provisionprofile'
    if not path.is_file():
        sys.exit('Missing dedicated ' + bundle + ' profile. Connect the Apple Developer account in Xcode Settings > Accounts, then run scripts/provision.py. No app was packaged.')
    result = subprocess.run(['security', 'cms', '-D', '-i', str(path)], check=True, capture_output=True)
    value = plistlib.loads(result.stdout)
    entitlement = value.get('Entitlements', {})
    if (value.get('TeamIdentifier') != [TEAM]
        or not permits_identifier(entitlement.get('com.apple.application-identifier'), TEAM + '.' + bundle)
        or value.get('ExpirationDate', datetime.datetime.min) <= datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        or 'OSX' not in value.get('Platform', [])):
        sys.exit('Dedicated provisioning profile has the wrong identity/platform or is expired: ' + bundle)
    permitted = entitlement.get('keychain-access-groups', [])
    if not any(permits_identifier(pattern, group) for pattern in permitted):
        sys.exit('Dedicated provisioning profile does not permit its exclusive Keychain group: ' + bundle)
    identities = subprocess.run(['security', 'find-identity', '-v', '-p', 'codesigning'], check=True, capture_output=True, text=True).stdout
    valid = set(re.findall(r'\b[0-9A-F]{40}\b', identities))
    candidates = [hashlib.sha1(data).hexdigest().upper() for data in value.get('DeveloperCertificates', [])]
    match = next((candidate for candidate in candidates if candidate in valid), None)
    if match is None:
        sys.exit('No local signing identity matches the dedicated provisioning profile: ' + bundle)
    return path, match

signer_id, engine_id = 'com.agent-yhes.YhesSigner', 'com.agent-yhes.engine'
signer_profile, signer_cert = profile('SignerProfile', signer_id, TEAM + '.' + signer_id)
engine_profile, engine_cert = profile('EngineProfile', engine_id, TEAM + '.' + engine_id + '.vault')
if sys.argv[1:] == ['--check-profiles']:
    print('Both dedicated app IDs and exclusive Keychain groups are authorized by current local macOS profiles with matching local signing identities.')
    sys.exit(0)
# Team pin is a compiler input. The engine does not read it from runtime env.
environment = dict(os.environ, YHES_SIGNING_TEAM=TEAM)
subprocess.run(['cargo', 'build', '--manifest-path', str(REPO / 'secure/Cargo.toml'), '--locked', '--release', '--target-dir', str(ROOT / '.build/engine'), '-p', 'yhes-cli'], env=environment, check=True)
subprocess.run([str(ROOT / 'scripts/prepare-validator.sh')], check=True)
subprocess.run(['swift', 'build', '--package-path', str(ROOT), '-c', 'release'], check=True)
swift_bin = subprocess.run(['swift', 'build', '--package-path', str(ROOT), '-c', 'release', '--show-bin-path'], check=True, capture_output=True, text=True).stdout.strip()
# Stage under our own build tree; failed packaging never replaces the previous app.
staging = ROOT / 'build/SignedStaging'
staging.mkdir(parents=True, exist_ok=True)
app = staging / 'YhesSigner.app'
if app.exists(): shutil.rmtree(app)
(app / 'Contents/MacOS').mkdir(parents=True)
engine = app / 'Contents/Helpers/Engine.app'
(engine / 'Contents/MacOS').mkdir(parents=True)
shutil.copy2(Path(swift_bin) / 'YhesSigner', app / 'Contents/MacOS/YhesSigner')
shutil.copy2(ROOT / '.build/engine/release/yhes', engine / 'Contents/MacOS/yhes')
shutil.copy2(ROOT / 'Bundle/Info.plist', app / 'Contents/Info.plist')
(engine / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': engine_id, 'CFBundleName': 'Yhes Engine', 'CFBundleExecutable': 'yhes', 'CFBundlePackageType': 'APPL', 'CFBundleVersion': '1', 'CFBundleShortVersionString': '0.1.0', 'LSMinimumSystemVersion': '14.0', 'LSUIElement': True}))
for target, bundle, provision, cert, suffix in [(engine, engine_id, engine_profile, engine_cert, '.vault'), (app, signer_id, signer_profile, signer_cert, '')]:
    shutil.copy2(provision, target / 'Contents/embedded.provisionprofile')
    entitlements = staging / (bundle + '.entitlements')
    entitlements.write_bytes(plistlib.dumps({'com.apple.application-identifier': TEAM + '.' + bundle, 'com.apple.developer.team-identifier': TEAM, 'keychain-access-groups': [TEAM + '.' + bundle + suffix]}))
    if target == app:
        (app / 'Contents/Helpers/yhes').symlink_to('Engine.app/Contents/MacOS/yhes')
    subprocess.run(['codesign', '--force', '--sign', cert, '--options', 'runtime', '--timestamp=none', '--entitlements', str(entitlements), str(target)], check=True)
    requirement = 'anchor apple generic and identifier \"' + bundle + '\" and certificate leaf[subject.OU] = \"' + TEAM + '\"'
    subprocess.run(['codesign', '--verify', '--strict', '--verbose=2', '-R', '=' + requirement, str(target)], check=True)
    signed = plistlib.loads(subprocess.run(['codesign', '-d', '--entitlements', ':-', str(target)], check=True, capture_output=True).stdout)
    expected = plistlib.loads(entitlements.read_bytes())
    if signed != expected:
        sys.exit('Signed entitlements differ from the exact dedicated identity/group: ' + bundle)
final = ROOT / 'build/YhesSigner.app'
previous = ROOT / 'build/PreviousYhesSigner.app'
if previous.exists(): shutil.rmtree(previous)
if final.exists(): final.rename(previous)
app.rename(final)
print(final)
print('Locally signed and provisioned; not launched, notarized, uploaded or enrolled.')
