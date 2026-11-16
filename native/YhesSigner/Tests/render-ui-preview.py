#!/usr/bin/env python3
"""Build inert AppKit fixtures for manual/CUA visual QA; never launches the app.

Run swift build first. This copies App.swift to a temporary test compilation,
exposes its view state there, and disconnects every production control action.
It never invokes service startup, setup, Keychain, enrollment or signing.
Open build/UXPreviews/YhesUXPreview.app and use Fixtures (Cmd+1 through Cmd+9).
The separate bundle ID cannot satisfy TrustedApplication's production identity.
"""
from pathlib import Path
import plistlib, subprocess, tempfile
root=Path(__file__).resolve().parents[1]
tmp=Path(tempfile.mkdtemp(prefix='yhes-live-preview-'))
(tmp/'App.swift').write_text((root/'Sources/YhesSigner/App.swift').read_text().replace('private ', ''))
appdir=root/'build/UXPreviews/YhesUXPreview.app'
(appdir/'Contents/MacOS').mkdir(parents=True,exist_ok=True)
(appdir/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':'com.agent-yhes.UXPreview','CFBundleExecutable':'Preview','CFBundleName':'Yhes UX Preview','CFBundlePackageType':'APPL'}))
main=r'''
import AppKit
import Foundation
import YhesSignerCore
@MainActor final class PreviewController: NSObject, NSApplicationDelegate {
    let ui = SignerApp()
    func applicationDidFinishLaunching(_ notification: Notification) {
        ui.buildWindow()
        // Static view harness: no listener, backend, setup runner, or actions.
        func inert(_ view: NSView) {
            if let control = view as? NSControl { control.action = nil; control.target = nil }
            for subview in view.subviews { inert(subview) }
        }
        inert(ui.window.contentView!)
        let bar = NSMenu(), appItem = NSMenuItem(), appMenu = NSMenu()
        appMenu.addItem(withTitle: "Quit Preview", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu; bar.addItem(appItem)
        let item = NSMenuItem(title: "Fixtures", action: nil, keyEquivalent: ""), menu = NSMenu(title:"Fixtures")
        for (index,title) in ["Light home", "Dark small home", "Light identity", "Dark small retry", "Light team", "Dark cancelled", "Light permissions", "Dark small channel", "Complete details"].enumerated() {
            let fixture = NSMenuItem(title: title, action: #selector(showFixture(_:)), keyEquivalent: String(index+1)); fixture.target = self; fixture.tag = index; menu.addItem(fixture)
        }
        item.submenu = menu; bar.addItem(item); NSApp.mainMenu = bar
        showFixture(menu.items[0]); NSApp.activate(ignoringOtherApps: true)
    }
    @objc func showFixture(_ sender: NSMenuItem) {
        let fixture = sender.tag, dark = [1,3,5,7].contains(fixture), small = [1,3,7].contains(fixture)
        ui.window.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
        ui.window.setContentSize(NSSize(width: small ? 640 : 720, height: small ? 520 : 560))
        ui.listenerReady = true; ui.request = nil; ui.awaitingNextStep = false; ui.manualEnrollment = nil; ui.approval.invalidate(); ui.outcome=nil; ui.retryAvailable=false
        ui.humanField.stringValue="alice"; ui.projectField.stringValue="demo"; ui.folderField.stringValue="/Projects/demo"
        ui.identityLabel.stringValue="No device key yet. Your first approval creates it for one human and project."
        ui.home(); ui.status.stringValue="Choose an existing project folder to begin. No Terminal command is needed."
        if fixture == 2 || fixture == 3 {
            let value: [String:Any] = ["version":1,"id":UUID().uuidString,"operation":"enroll","author":"alice","project":"demo","mode":NSNull(),"payloads":[],"request":NSNull()]
            ui.request=try! SignerRequest.parse(JSONSerialization.data(withJSONObject:value))
            ui.heading.stringValue="Set up your signing key"
            ui.notice.stringValue="Key setup requested by the signed local CLI. Check the author and project before continuing."
            ui.summary.string="Human ID: alice\nProject ID: demo\n\nCreate this Mac’s signing key for this human and project. The private key stays in Secure Enclave and cannot be exported. This key can be used only for this project.\n\nOnly your public identity is returned. Next you will review the team and its permissions. Existing keys are never replaced."
            ui.status.stringValue="Review this identity, then create the key with fresh Touch ID."
            if fixture == 3 { ui.retryAvailable=true; ui.status.stringValue="Touch ID was cancelled. No approval was returned. Review the same request and try again, or cancel it." }
        }
        if fixture == 4 || fixture == 8 {
            let registry=try! ValidatedRegistry.parse(Data(contentsOf:URL(fileURLWithPath:"FIXTURE")))
            ui.approval.replace(with:.registry(registry)); ui.heading.stringValue=ui.approval.document!.reviewHeading; ui.summary.string=ui.approval.document!.reviewText
            ui.notice.stringValue="Unapproved request. Approval applies only to the identities and keys shown here."
            ui.displayExactPayloads()
            ui.status.stringValue="Check every identity, key and revocation before approving."
        }
        if fixture == 5 { ui.outcome="Request cancelled. No approval was returned. Resume setup when you are ready."; ui.outcomeHeading="Request cancelled"; ui.home(); ui.status.stringValue="Progress is saved. Resume checks completed steps before continuing." }
        if fixture == 6 || fixture == 7 {
            let key = "k_" + String(repeating: "b", count: 64)
            var body: [String: Any] = ["agent":"codex", "agent_key_id":key, "purposes":["action.execute","agent.message","agent.relay","ticket.action"]]
            var action: ActionRequest?
            if fixture == 7 {
                action = try! ActionRequest.parse(JSONSerialization.data(withJSONObject:["version":1,"project":"demo","action":"group.add","performer":"codex","group":"team","epoch":1,"audience":["alice","claude","codex"],"parameters":["member":"claude","key_id":key,"key_package_digest":String(repeating:"c",count:64)]]))
                body=["action":"group.add","performer":"codex","request_digest":action!.digest]
            }
            let value=try! ValidatedEvent.parse(JSONSerialization.data(withJSONObject:["version":1,"id":"preview-event","project":"demo","kind":fixture == 6 ? "agent.delegation" : "action.authorization","author":"alice","key_id":key,"session":NSNull(),"issued_at":2000000000,"expires_at":2000000300,"audience":["alice","claude","codex"],"group":"team","epoch":1,"previous":NSNull(),"body":body]))
            ui.approval.replace(with:.event(value,action)); ui.heading.stringValue=ui.approval.document!.reviewHeading; ui.summary.string=ui.approval.document!.reviewText
            ui.notice.stringValue="Approval applies only to the capabilities, scope and recipients shown here."
            ui.identityLabel.stringValue="Device key: alice · Project: demo · This key belongs to one project."
            ui.status.stringValue="Review every recipient and the complete scope before approving."
            ui.displayExactPayloads()
        }
        ui.refresh(); ui.window.title="Yhes UX Preview — " + sender.title
        ui.window.makeKeyAndOrderFront(nil)
        if fixture == 8 { ui.toggleDetails() }
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}
let app=NSApplication.shared; app.setActivationPolicy(.regular)
let controller=PreviewController(); app.delegate=controller; app.run()
'''
main=main.replace('FIXTURE',str(root/'Tests/YhesSignerCoreTests/Fixtures/p256-registry-payload.json'))
(tmp/'main.swift').write_text(main)
sources=[str(p) for p in (root/'Sources/YhesSigner').glob('*.swift') if p.name not in ['main.swift','App.swift']]
products=root/'.build/out/Products/Debug'
subprocess.run(['swiftc','-swift-version','6','-target','arm64-apple-macos14.0','-I',str(products),'-Xcc','-fmodule-map-file='+str(root/'.build/out/Intermediates.noindex/GeneratedModuleMaps/CYhesWire.modulemap'),str(tmp/'App.swift'),*sources,str(tmp/'main.swift'),str(products/'libYhesSignerCore.a'),str(products/'CYhesWire.o'),str(root/'.build/rust/release/libyhes_wire_ffi.a'),'-o',str(appdir/'Contents/MacOS/Preview')],check=True)
print(appdir)
