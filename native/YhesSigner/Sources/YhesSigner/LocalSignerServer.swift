import Darwin
import Foundation
import YhesSignerCore

/// Bounded single-frame transport. Authentication and liveness are independent
/// of JSON input. No received bytes or error descriptions enter logs.
final class LocalSignerConnection: @unchecked Sendable {
    let token = UUID()
    private let descriptor: Int32
    private let lock = NSLock()
    private var alive = true
    private var reply: Data?
    private var requestID = SignerResponse.invalidID
    private let onRequest: @MainActor @Sendable (LocalSignerConnection, SignerRequest) -> Void
    private let onDisconnect: @MainActor @Sendable (UUID) -> Void
    init(descriptor: Int32,
         onRequest: @escaping @MainActor @Sendable (LocalSignerConnection, SignerRequest) -> Void,
         onDisconnect: @escaping @MainActor @Sendable (UUID) -> Void) {
        self.descriptor = descriptor; self.onRequest = onRequest; self.onDisconnect = onDisconnect
    }
    var isLive: Bool {
        lock.lock(); defer { lock.unlock() }
        guard alive else { return false }
        var byte: UInt8 = 0
        let count = recv(descriptor, &byte, 1, MSG_PEEK | MSG_DONTWAIT)
        return count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)
    }
    @discardableResult func respond(_ data: Data) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard alive, reply == nil else { return false }
        reply = data; return true
    }
    func fail(_ code: SignerProtocolError) { _ = respond(SignerResponse.failure(id: requestID, code: code)) }
    func cancel() {
        lock.lock(); defer { lock.unlock() }
        guard alive else { return }
        alive = false
        // Shutdown wakes the one worker; only that worker closes its descriptor.
        shutdown(descriptor, SHUT_RDWR)
    }
    private func finish() {
        lock.lock(); alive = false; close(descriptor); lock.unlock()
        Task { @MainActor in self.onDisconnect(self.token) }
    }
    func run() {
        defer { finish() }
        var noPipe: Int32 = 1
        _ = setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &noPipe, socklen_t(MemoryLayout<Int32>.size))
        _ = fcntl(descriptor, F_SETFL, O_NONBLOCK)
        do { try TrustedApplication.requireEnginePeer(socket: descriptor) }
        catch { write(SignerResponse.failure(id: requestID, code: .unauthorized)); return }
        let inputDeadline = ProcessInfo.processInfo.systemUptime + 10
        var input = Data()
        var complete = false
        while !complete && ProcessInfo.processInfo.systemUptime < inputDeadline {
            var p = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
            let ready = poll(&p, 1, 100)
            if ready < 0 { if errno == EINTR { continue }; return }
            if ready == 0 { continue }
            var bytes = [UInt8](repeating: 0, count: 8192)
            let n = recv(descriptor, &bytes, bytes.count, 0)
            guard n > 0 else { return }
            input.append(contentsOf: bytes.prefix(n))
            guard input.count <= SignerRequest.maxFrameBytes + 1 else {
                write(SignerResponse.failure(id: requestID, code: .invalidRequest)); return
            }
            if let newline = input.firstIndex(of: 10) {
                guard newline == input.index(before: input.endIndex) else {
                    write(SignerResponse.failure(id: requestID, code: .invalidRequest)); return
                }
                input.removeLast(); complete = true
            }
        }
        guard complete else { write(SignerResponse.failure(id: requestID, code: .timeout)); return }
        let request: SignerRequest
        do { request = try SignerRequest.parse(input) }
        catch { write(SignerResponse.failure(id: requestID, code: error as? SignerProtocolError ?? .invalidRequest)); return }
        input.removeAll(keepingCapacity: false)
        requestID = request.id
        Task { @MainActor in self.onRequest(self, request) }
        let reviewDeadline = ProcessInfo.processInfo.systemUptime + 300
        while ProcessInfo.processInfo.systemUptime < reviewDeadline {
            // Extra bytes and EOF invalidate consent before delivery. A client
            // must keep its write half open until it receives the response.
            guard isLive else { return }
            lock.lock(); let output = reply; let active = alive; lock.unlock()
            guard active else { return }
            if let output { write(output); return }
            var p = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
            _ = poll(&p, 1, 100)
        }
        write(SignerResponse.failure(id: requestID, code: .timeout))
    }
    private func write(_ data: Data) {
        let deadline = ProcessInfo.processInfo.systemUptime + 2
        data.withUnsafeBytes { bytes in
            var sent = 0
            while sent < bytes.count && ProcessInfo.processInfo.systemUptime < deadline {
                let n = send(descriptor, bytes.baseAddress!.advanced(by: sent), bytes.count - sent, 0)
                if n > 0 { sent += n; continue }
                if errno == EINTR { continue }
                guard errno == EAGAIN || errno == EWOULDBLOCK else { return }
                var p = pollfd(fd: descriptor, events: Int16(POLLOUT), revents: 0)
                _ = poll(&p, 1, 100)
            }
        }
    }
}

final class LocalSignerServer: @unchecked Sendable {
    private let lock = NSLock()
    private var connections: [UUID: LocalSignerConnection] = [:]
    private var source: DispatchSourceRead?
    private var directoryFD: Int32 = -1
    private var lockFD: Int32 = -1
    private var listener: Int32 = -1
    private var socketInode: ino_t = 0
    private let queue = DispatchQueue(label: "com.agent-yhes.signer.listener")
    private let onRequest: @MainActor @Sendable (LocalSignerConnection, SignerRequest) -> Void
    private let onDisconnect: @MainActor @Sendable (UUID) -> Void
    init(onRequest: @escaping @MainActor @Sendable (LocalSignerConnection, SignerRequest) -> Void,
         onDisconnect: @escaping @MainActor @Sendable (UUID) -> Void) {
        self.onRequest = onRequest; self.onDisconnect = onDisconnect
    }
    func start() throws {
        try TrustedApplication.requireProtectedIdentity()
        let support = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/agent-yhes")
        if mkdir(support.path, 0o700) != 0 && errno != EEXIST { throw SignerProtocolError.unavailable }
        directoryFD = open(support.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        var st = stat()
        guard directoryFD >= 0, fstat(directoryFD, &st) == 0,
              st.st_uid == getuid(), st.st_mode & 0o777 == 0o700 else { stop(); throw SignerProtocolError.unavailable }
        lockFD = openat(directoryFD, "signer.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard lockFD >= 0, fstat(lockFD, &st) == 0, st.st_uid == getuid(),
              st.st_mode & S_IFMT == S_IFREG, st.st_mode & 0o777 == 0o600,
              flock(lockFD, LOCK_EX | LOCK_NB) == 0 else { stop(); throw SignerProtocolError.busy }
        let path = support.appendingPathComponent("signer.sock").path
        if fstatat(directoryFD, "signer.sock", &st, AT_SYMLINK_NOFOLLOW) == 0 {
            guard st.st_mode & S_IFMT == S_IFSOCK, st.st_uid == getuid() else { stop(); throw SignerProtocolError.unavailable }
            // The file lock is held before stale cleanup. Every listener uses it.
            guard unlinkat(directoryFD, "signer.sock", 0) == 0 else { stop(); throw SignerProtocolError.unavailable }
        } else if errno != ENOENT { stop(); throw SignerProtocolError.unavailable }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8) + [0]
        guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else { stop(); throw SignerProtocolError.unavailable }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        listener = socket(AF_UNIX, SOCK_STREAM, 0)
        guard listener >= 0 else { stop(); throw SignerProtocolError.unavailable }
        _ = fcntl(listener, F_SETFD, FD_CLOEXEC)
        _ = fcntl(listener, F_SETFL, O_NONBLOCK)
        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard bound == 0, fchmodat(directoryFD, "signer.sock", 0o600, 0) == 0,
              fstatat(directoryFD, "signer.sock", &st, AT_SYMLINK_NOFOLLOW) == 0,
              listen(listener, 8) == 0 else { stop(); throw SignerProtocolError.unavailable }
        socketInode = st.st_ino
        let source = DispatchSource.makeReadSource(fileDescriptor: listener, queue: queue)
        source.setEventHandler { [weak self] in self?.acceptConnections() }
        self.source = source; source.resume()
    }
    private func acceptConnections() {
        let fd = accept(listener, nil, nil)
        guard fd >= 0 else { return }
        _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
        lock.lock()
        guard connections.count < 8 else { lock.unlock(); close(fd); return }
        let connection = LocalSignerConnection(descriptor: fd, onRequest: onRequest, onDisconnect: onDisconnect)
        connections[connection.token] = connection
        lock.unlock()
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            connection.run()
            guard let self else { return }
            self.lock.lock(); self.connections.removeValue(forKey: connection.token); self.lock.unlock()
        }
    }
    func stop() {
        queue.sync {
            source?.cancel(); source = nil
            if listener >= 0 { close(listener); listener = -1 }
        }
        lock.lock(); let active = Array(connections.values); connections.removeAll(); lock.unlock()
        active.forEach { $0.cancel() }
        if socketInode != 0, directoryFD >= 0 {
            var st = stat()
            if fstatat(directoryFD, "signer.sock", &st, AT_SYMLINK_NOFOLLOW) == 0, st.st_ino == socketInode {
                _ = unlinkat(directoryFD, "signer.sock", 0)
            }
        }
        socketInode = 0
        if lockFD >= 0 { close(lockFD); lockFD = -1 }
        if directoryFD >= 0 { close(directoryFD); directoryFD = -1 }
    }
}
