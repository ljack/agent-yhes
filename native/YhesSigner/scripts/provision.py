#!/usr/bin/env python3
"""Prepare dedicated Xcode local development profiles. Does not archive/upload."""
from pathlib import Path
import plistlib
import platform
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

root = Path(__file__).resolve().parent.parent
work = root / 'build' / 'Provisioning'
work.mkdir(parents=True, exist_ok=True)
(work / 'main.swift').write_text('import Foundation\nprint("Provisioning preparation only")\n')
objects = {}
def add(key, value):
    objects[key] = value
    return key
project = add('000000000000000000000001', {'isa': 'PBXProject', 'attributes': {'LastUpgradeCheck': '2700', 'TargetAttributes': {}}, 'buildConfigurationList': '000000000000000000000002', 'compatibilityVersion': 'Xcode 14.0', 'mainGroup': '000000000000000000000003', 'productRefGroup': '000000000000000000000004', 'projectDirPath': '', 'projectRoot': '', 'targets': []})
add('000000000000000000000002', {'isa': 'XCConfigurationList', 'buildConfigurations': ['000000000000000000000005'], 'defaultConfigurationIsVisible': '0', 'defaultConfigurationName': 'Release'})
add('000000000000000000000005', {'isa': 'XCBuildConfiguration', 'buildSettings': {}, 'name': 'Release'})
add('000000000000000000000003', {'isa': 'PBXGroup', 'children': ['000000000000000000000004', '000000000000000000000006'], 'sourceTree': '<group>'})
add('000000000000000000000004', {'isa': 'PBXGroup', 'children': [], 'name': 'Products', 'sourceTree': '<group>'})
add('000000000000000000000006', {'isa': 'PBXFileReference', 'lastKnownFileType': 'sourcecode.swift', 'path': 'main.swift', 'sourceTree': '<group>'})
for index, (name, bundle) in enumerate([('SignerProfile', 'com.agent-yhes.YhesSigner'), ('EngineProfile', 'com.agent-yhes.engine')], 1):
    def ident(n): return f'{index:012x}{n:012x}'
    group = '25C9H9N953.' + bundle
    (work / (name + '.entitlements')).write_bytes(plistlib.dumps({'com.apple.application-identifier': group, 'com.apple.developer.team-identifier': '25C9H9N953', 'keychain-access-groups': [group + ('.vault' if name == 'EngineProfile' else '')]}))
    target = add(ident(1), {'isa': 'PBXNativeTarget', 'buildConfigurationList': ident(2), 'buildPhases': [ident(4)], 'buildRules': [], 'dependencies': [], 'name': name, 'productName': name, 'productReference': ident(6), 'productType': 'com.apple.product-type.application'})
    objects[project]['targets'].append(target)
    objects[project]['attributes']['TargetAttributes'][target] = {'ProvisioningStyle': 'Automatic', 'SystemCapabilities': {'com.apple.Keychain': {'enabled': '1'}}}
    add(ident(2), {'isa': 'XCConfigurationList', 'buildConfigurations': [ident(3)], 'defaultConfigurationIsVisible': '0', 'defaultConfigurationName': 'Release'})
    add(ident(3), {'isa': 'XCBuildConfiguration', 'name': 'Release', 'buildSettings': {'PRODUCT_NAME': name, 'PRODUCT_BUNDLE_IDENTIFIER': bundle, 'SDKROOT': 'macosx', 'MACOSX_DEPLOYMENT_TARGET': '14.0', 'SWIFT_VERSION': '6.0', 'GENERATE_INFOPLIST_FILE': 'YES', 'CODE_SIGN_STYLE': 'Automatic', 'CODE_SIGN_IDENTITY': 'Apple Development', 'DEVELOPMENT_TEAM': '25C9H9N953', 'CODE_SIGN_ENTITLEMENTS': name + '.entitlements', 'ENABLE_HARDENED_RUNTIME': 'YES', 'ENABLE_APP_SANDBOX': 'NO', 'CODE_SIGN_INJECT_BASE_ENTITLEMENTS': 'NO', 'DEBUG_INFORMATION_FORMAT': 'dwarf', 'ALWAYS_SEARCH_USER_PATHS': 'NO', 'ONLY_ACTIVE_ARCH': 'YES'}})
    add(ident(4), {'isa': 'PBXSourcesBuildPhase', 'buildActionMask': '2147483647', 'files': [ident(5)], 'runOnlyForDeploymentPostprocessing': '0'})
    add(ident(5), {'isa': 'PBXBuildFile', 'fileRef': '000000000000000000000006'})
    add(ident(6), {'isa': 'PBXFileReference', 'explicitFileType': 'wrapper.application', 'includeInIndex': '0', 'path': name + '.app', 'sourceTree': 'BUILT_PRODUCTS_DIR'})
    objects['000000000000000000000004']['children'].append(ident(6))
proj = work / 'LocalProfiles.xcodeproj'
proj.mkdir(exist_ok=True)
(proj / 'project.pbxproj').write_bytes(plistlib.dumps({'archiveVersion': '1', 'classes': {}, 'objectVersion': '56', 'objects': objects, 'rootObject': project}))
# -alltargets has no concrete run destination and cannot register this Mac.
# Shared schemes plus an explicit physical-Mac destination let Xcode provision
# these two IDs using the signed-in team's local development device.
schemes = proj / 'xcshareddata/xcschemes'
schemes.mkdir(parents=True, exist_ok=True)
for target in objects[project]['targets']:
    name = objects[target]['name']
    scheme = ET.Element('Scheme', LastUpgradeVersion='2700', version='1.3')
    action = ET.SubElement(scheme, 'BuildAction', parallelizeBuildables='YES', buildImplicitDependencies='YES')
    entry = ET.SubElement(ET.SubElement(action, 'BuildActionEntries'), 'BuildActionEntry', buildForTesting='NO', buildForRunning='YES', buildForProfiling='YES', buildForArchiving='NO', buildForAnalyzing='YES')
    ET.SubElement(entry, 'BuildableReference', BuildableIdentifier='primary', BlueprintIdentifier=target, BuildableName=name + '.app', BlueprintName=name, ReferencedContainer='container:LocalProfiles.xcodeproj')
    ET.ElementTree(scheme).write(schemes / (name + '.xcscheme'), encoding='UTF-8', xml_declaration=True)

result = subprocess.run(['xcodebuild', '-project', str(proj), '-scheme', 'SignerProfile', '-showdestinations'], capture_output=True, text=True, check=True)
machine_arch = platform.machine()
destination = None
for line in result.stdout.splitlines():
    if 'platform:macOS' not in line or 'name:My Mac' not in line:
        continue
    fields = dict(re.findall(r'(platform|arch|id|name):([^,}]+)', line))
    fields = {key: value.strip() for key, value in fields.items()}
    if fields.get('arch') == machine_arch and fields.get('id'):
        destination = 'platform=macOS,arch=' + machine_arch + ',id=' + fields['id']
        break
if destination is None:
    sys.exit('Xcode did not expose this Mac as a development destination. Open Xcode and check the signed-in team and supported macOS destination.')
for name in ['SignerProfile', 'EngineProfile']:
    subprocess.run(['xcodebuild', '-project', str(proj), '-scheme', name, '-destination', destination, '-configuration', 'Release', '-allowProvisioningUpdates', '-allowProvisioningDeviceRegistration', 'build', 'CONFIGURATION_BUILD_DIR=' + str(work / 'Products')], check=True)
