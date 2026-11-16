import Foundation
import Security
import YhesSignerCore

/// Launches one fixed command from the signed bundle. Context is navigation,
/// never authority; every protected operation still arrives through the server.
@MainActor
final class SetupRunner {
    private var process: Process?
    private var output = Capture()
    var isRunning: Bool { process != nil }
    var diagnostics: (stdout: SetupOutput, stderr: SetupOutput) { output.snapshot() }

    func start(_ context: SetupContext, completion: @escaping @MainActor @Sendable (Int32, SetupOutput, SetupOutput) -> Void) throws {
        guard process == nil else { throw SignerError.invalid("Setup is already running.") }
        try TrustedApplication.requireProtectedIdentity()
        let helper = try Self.verifiedHelper()
        let folder = URL(fileURLWithPath: context.folder).standardizedFileURL.resolvingSymlinksInPath()
        let values = try folder.resourceValues(forKeys: [.isDirectoryKey])
        guard values.isDirectory == true else { throw SignerError.invalid("Choose an existing project folder.") }
        let child = Process()
        child.executableURL = helper
        child.currentDirectoryURL = folder
        child.arguments = try SetupContext(folder: folder.path, human: context.human, project: context.project).arguments
        // No inherited DYLD, executable override, shell, or caller-selected helper.
        child.environment = ["HOME": NSHomeDirectory(), "PATH": "/usr/bin:/bin", "TMPDIR": NSTemporaryDirectory()]
        child.standardInput = FileHandle.nullDevice
        let stdout = Pipe(), stderr = Pipe(), reads = DispatchGroup(), capture = Capture()
        output = capture
        child.standardOutput = stdout; child.standardError = stderr
        reads.enter(); reads.enter()
        child.terminationHandler = { [weak self] child in
            reads.notify(queue: .global(qos: .utility)) { [weak self] in
                let result = capture.snapshot(), code = child.terminationStatus
                Task { @MainActor [weak self] in
                    self?.process = nil
                    completion(code, result.stdout, result.stderr)
                }
            }
        }
        do { try child.run() }
        catch {
            // No readers were started, so this path owns both group entries.
            child.terminationHandler = nil
            reads.leave(); reads.leave()
            throw error
        }
        process = child
        for (handle, isError) in [(stdout.fileHandleForReading, false), (stderr.fileHandleForReading, true)] {
            DispatchQueue.global(qos: .utility).async {
                defer { try? handle.close(); reads.leave() }
                while let bytes = try? handle.read(upToCount: 4096), !bytes.isEmpty { capture.append(bytes, isError: isError) }
            }
        }
    }

    func cancel() { process?.terminate() }

    private static func verifiedHelper() throws -> URL {
        let bundle = Bundle.main.bundleURL.resolvingSymlinksInPath()
        let engine = bundle.appendingPathComponent("Contents/Helpers/Engine.app")
        let executable = engine.appendingPathComponent("Contents/MacOS/yhes")
        guard engine.resolvingSymlinksInPath().path == engine.path,
              executable.resolvingSymlinksInPath().path == executable.path,
              FileManager.default.isExecutableFile(atPath: executable.path) else {
            throw SignerError.invalid("The bundled setup helper is missing or has moved. Reinstall the signed app.")
        }
        var code: SecStaticCode?, requirement: SecRequirement?
        let expression = "anchor apple generic and identifier \"\(TrustedApplication.engineID)\" and certificate leaf[subject.OU] = \"\(TrustedApplication.teamID)\""
        guard SecStaticCodeCreateWithPath(engine as CFURL, [], &code) == errSecSuccess, let code,
              SecRequirementCreateWithString(expression as CFString, [], &requirement) == errSecSuccess, let requirement,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures), requirement) == errSecSuccess else {
            throw SignerError.invalid("The bundled setup helper failed its signature check. Reinstall the signed app.")
        }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let info = information as? [String: Any],
              let flags = info[kSecCodeInfoFlags as String] as? UInt32, flags & 0x10000 != 0,
              let entitlements = info[kSecCodeInfoEntitlementsDict as String] as? [String: Any],
              entitlements["com.apple.application-identifier"] as? String == TrustedApplication.teamID + "." + TrustedApplication.engineID,
              entitlements["keychain-access-groups"] as? [String] == [TrustedApplication.teamID + "." + TrustedApplication.engineID + ".vault"] else {
            throw SignerError.invalid("The bundled setup helper has an unexpected protected identity.")
        }
        let forbidden = ["com.apple.security.get-task-allow", "com.apple.security.cs.disable-library-validation", "com.apple.security.cs.allow-dyld-environment-variables", "com.apple.security.cs.allow-unsigned-executable-memory", "com.apple.security.cs.allow-jit"]
        guard forbidden.allSatisfy({ (entitlements[$0] as? Bool) != true }) else { throw SignerError.invalid("The bundled setup helper has unsafe entitlements.") }
        return executable
    }

    private final class Capture: @unchecked Sendable {
        private let lock = NSLock()
        private var stdout = SetupOutput(), stderr = SetupOutput()
        func append(_ bytes: Data, isError: Bool) {
            lock.lock(); defer { lock.unlock() }
            if isError { stderr.append(bytes) } else { stdout.append(bytes) }
        }
        func snapshot() -> (stdout: SetupOutput, stderr: SetupOutput) {
            lock.lock(); defer { lock.unlock() }; return (stdout, stderr)
        }
    }
}
