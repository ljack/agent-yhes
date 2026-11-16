import AppKit
import Foundation

if CommandLine.arguments.count != 1 {
    let help = "YhesSigner is a native review application. Launch without arguments. No CLI signing or enrollment commands are available.\n"
    FileHandle.standardError.write(Data(help.utf8))
    exit(CommandLine.arguments.dropFirst() == ["--help"] ? 0 : 64)
}
let app = NSApplication.shared
app.setActivationPolicy(.regular)
let delegate = SignerApp()
app.delegate = delegate
app.run()
