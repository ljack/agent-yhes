import Darwin
import Foundation
import YhesSignerCore

/// Read only the regular file intentionally selected in the native picker.
/// No pipes/devices, final symlinks, unbounded reads, or later path re-opening.
enum NativeDraftFile {
    static func read(_ url: URL) throws -> Data {
        let descriptor = url.withUnsafeFileSystemRepresentation { path in
            path.map { Darwin.open($0, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC) } ?? -1
        }
        guard descriptor >= 0 else { throw SignerError.invalid("Cannot open this draft as a regular file.") }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? handle.close() }
        var information = stat()
        guard fstat(descriptor, &information) == 0, information.st_mode & S_IFMT == S_IFREG,
              information.st_size > 0, information.st_size <= StrictJSON.maxBytes else {
            throw SignerError.invalid("Select a regular JSON file of at most 65,536 bytes.")
        }
        // The immutable returned snapshot, not the file path, is reviewed/signed.
        return try handle.read(upToCount: StrictJSON.maxBytes + 1) ?? Data()
    }
}
