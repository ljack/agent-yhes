import AppKit
import LocalAuthentication
import Security
import UniformTypeIdentifiers
import YhesSignerCore

@MainActor
final class SignerApp: NSObject, NSApplicationDelegate, NSWindowDelegate, NSTextFieldDelegate {
    private let backend = SecureEnclaveRoot()
    private var identity: SigningIdentity?
    private var approval = ReviewState()
    private var busy = false
    private var workerID: UUID?
    private var attempts = ApprovalAttempts()
    private var actionArming = ApprovalActionArming()
    private var interaction = ManualReviewGate()
    private var manualEnrollment: (human: String, project: String)?
    private var awaitingNextStep = false
    private var armingTimer: Timer?
    private var server: LocalSignerServer?
    private var pending = PendingReview()
    private var connection: LocalSignerConnection?
    private var request: SignerRequest?
    private var listenerReady = false
    private let setup = SetupRunner()
    private var setupContext: SetupContext?
    private var setupTimer: Timer?
    private var setupStage: SetupStage = .identity
    private var setupComplete = false
    private var setupAttempted = false
    private var outcome: String?
    private var outcomeHeading = "Setup paused"
    private var retryAvailable = false
    private var lastRequestContext: (human: String, project: String)?
    private let heading = NSTextField(labelWithString: "Set up your local team")
    private let notice = NSTextField(wrappingLabelWithString: "Connect Codex and Claude in an existing project. You review each protected step here.")
    private var window: NSWindow!
    private let status = NSTextField(wrappingLabelWithString: "Checking local signer…")
    private let identityLabel = NSTextField(wrappingLabelWithString: "Checking this app and device identity…")
    private let summary = NSTextView()
    private let exact = NSTextView()
    private var summaryScroll: NSScrollView!
    private var exactPanel: NSPanel?
    private var stepLabels: [NSTextField] = []
    private var setupForm: NSStackView!
    private let folderField = NSTextField(labelWithString: "Choose an existing project folder")
    private let humanField = NSTextField()
    private let projectField = NSTextField()
    private var chooseButton: NSButton!
    private var openButton: NSMenuItem!
    private var batchButton: NSMenuItem!
    private var registryButton: NSMenuItem!
    private var detailsButton: NSMenuItem!
    private var loadButton: NSMenuItem!
    private var createButton: NSMenuItem!
    private var exportButton: NSMenuItem!
    private var approveButton: NSButton!
    private var cancelButton: NSButton!
    private var observers: [NSObjectProtocol] = []

    func applicationDidFinishLaunching(_ notification: Notification) {
        buildMenus(); buildWindow(); restoreSetupContext(); startLocalService()
        let center = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.sessionDidResignActiveNotification, NSWorkspace.willSleepNotification, NSWorkspace.screensDidSleepNotification] {
            observers.append(center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.interrupt(.sessionInactive, message: "Request cancelled because this session is no longer active.") }
            })
        }
        observers.append(DistributedNotificationCenter.default().addObserver(forName: NSNotification.Name("com.apple.screenIsLocked"), object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.interrupt(.screenLocked, message: "Request cancelled because the screen locked.") }
        })
        NSApp.activate(ignoringOtherApps: true)
    }
    func applicationDidResignActive(_ notification: Notification) { interrupt(.focusChanged, message: "Focus changed.") }
    func applicationDidBecomeActive(_ notification: Notification) { refresh() }
    func windowDidBecomeKey(_ notification: Notification) { refresh() }
    func windowDidResignKey(_ notification: Notification) { interrupt(.focusChanged, message: "Focus changed.") }
    func applicationWillTerminate(_ notification: Notification) { interrupt(.appClosed, message: "Signer closed."); setup.cancel(); server?.stop() }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func windowWillClose(_ notification: Notification) {
        guard (notification.object as? NSWindow) === window else { return }
        interrupt(.appClosed, message: "Signer closed."); setup.cancel(); server?.stop()
    }
    private func interrupt(_ reason: ApprovalInterruption, message: String) {
        switch ApprovalActivity.decision(for: reason, hasFrozenAttempt: busy) {
        case .keepFrozenAttempt: break
        case .refresh: refresh()
        case .cancel:
            if reason == .screenLocked || reason == .sessionInactive || reason == .appClosed { setup.cancel() }
            invalidate(message)
        }
    }

    private func buildMenus() {
        let bar = NSMenu(), applicationItem = NSMenuItem(); bar.addItem(applicationItem)
        let application = NSMenu(); application.addItem(withTitle: "Quit Yhes Signer", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        applicationItem.submenu = application
        let editItem = NSMenuItem(); editItem.title = "Edit"; bar.addItem(editItem)
        let edit = NSMenu(title: "Edit")
        edit.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        edit.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editItem.submenu = edit; NSApp.mainMenu = bar
    }
    private func button(_ title: String, _ action: Selector) -> NSButton { NSButton(title: title, target: self, action: action) }
    private func advancedItem(_ title: String, _ action: Selector, menu: NSMenu) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: ""); item.target = self; menu.addItem(item); return item
    }
    private func buildWindow() {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 720, height: 560), styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "Yhes Signer"
        window.contentMinSize = NSSize(width: 640, height: 520)
        window.delegate = self
        armingTimer = Timer.scheduledTimer(withTimeInterval: 0.2, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.refresh() }
        }
        let root = NSStackView(); root.orientation = .vertical; root.alignment = .leading; root.spacing = 12
        root.edgeInsets = NSEdgeInsets(top: 20, left: 24, bottom: 20, right: 24)
        root.translatesAutoresizingMaskIntoConstraints = false
        window.contentView!.addSubview(root)
        NSLayoutConstraint.activate([root.leadingAnchor.constraint(equalTo: window.contentView!.leadingAnchor), root.trailingAnchor.constraint(equalTo: window.contentView!.trailingAnchor), root.topAnchor.constraint(equalTo: window.contentView!.topAnchor), root.bottomAnchor.constraint(equalTo: window.contentView!.bottomAnchor)])
        heading.font = .systemFont(ofSize: 22, weight: .semibold)
        root.addArrangedSubview(heading); root.addArrangedSubview(notice)
        let steps = NSStackView(); steps.spacing = 12
        for stage in SetupStage.allCases {
            if stage != .identity { steps.addArrangedSubview(NSTextField(labelWithString: "→")) }
            let label = NSTextField(labelWithString: "\(stage.rawValue + 1) \(stage.title)"); stepLabels.append(label); steps.addArrangedSubview(label)
        }
        steps.setAccessibilityLabel("Setup progress: Identity, Team, Permissions, Channel")
        root.addArrangedSubview(steps)
        identityLabel.font = .systemFont(ofSize: 12); identityLabel.textColor = .secondaryLabelColor
        root.addArrangedSubview(identityLabel)
        setupForm = NSStackView(); setupForm.orientation = .vertical; setupForm.alignment = .leading; setupForm.spacing = 10
        folderField.lineBreakMode = .byTruncatingMiddle; folderField.setAccessibilityLabel("Selected project folder")
        chooseButton = button("Choose folder…", #selector(chooseFolder))
        let folderRow = NSStackView(views: [folderField, chooseButton]); folderRow.spacing = 12
        folderField.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        folderField.setContentHuggingPriority(.defaultLow, for: .horizontal)
        setupForm.addArrangedSubview(folderRow)
        humanField.placeholderString = "Human ID"; humanField.setAccessibilityLabel("Human ID")
        projectField.placeholderString = "Project ID"; projectField.setAccessibilityLabel("Project ID")
        humanField.delegate = self; projectField.delegate = self
        let ids = NSStackView(views: [NSTextField(labelWithString: "Human ID"), humanField, NSTextField(labelWithString: "Project ID"), projectField]); ids.spacing = 8
        humanField.widthAnchor.constraint(greaterThanOrEqualToConstant: 100).isActive = true
        projectField.widthAnchor.constraint(equalTo: humanField.widthAnchor).isActive = true
        setupForm.addArrangedSubview(ids); root.addArrangedSubview(setupForm)
        for row in [folderRow, ids] { row.widthAnchor.constraint(equalTo: setupForm.widthAnchor).isActive = true }
        configureTextView(summary, label: "Action, full scope and every recipient", monospaced: false)
        summaryScroll = NSScrollView(); summaryScroll.hasVerticalScroller = true; summaryScroll.borderType = .bezelBorder; summaryScroll.documentView = summary
        root.addArrangedSubview(summaryScroll)
        summaryScroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 120).isActive = true
        summaryScroll.setContentHuggingPriority(.defaultLow, for: .vertical)
        configureTextView(exact, label: "Exact reviewed JSON and signature details", monospaced: true)
        status.font = .systemFont(ofSize: 12); status.setAccessibilityRole(.staticText)
        root.addArrangedSubview(status)
        let advanced = NSPopUpButton(frame: .zero, pullsDown: true)
        let menu = NSMenu(); menu.autoenablesItems = false
        menu.addItem(withTitle: "Advanced", action: nil, keyEquivalent: "")
        _ = advancedItem("Details: keys and exact JSON…", #selector(toggleDetails), menu: menu)
        _ = advancedItem("Show setup log…", #selector(showSetupLog), menu: menu)
        menu.addItem(.separator())
        openButton = advancedItem("Open event…", #selector(openDraft), menu: menu)
        detailsButton = advancedItem("Open action details…", #selector(openActionDetails), menu: menu)
        batchButton = advancedItem("Open statement batch…", #selector(openStatementBatch), menu: menu)
        registryButton = advancedItem("Open registry…", #selector(openRegistry), menu: menu)
        menu.addItem(.separator())
        loadButton = advancedItem("Reload device identity", #selector(loadIdentity), menu: menu)
        createButton = advancedItem("Set up device key manually…", #selector(createIdentity), menu: menu)
        exportButton = advancedItem("Save public identity…", #selector(exportIdentity), menu: menu)
        _ = advancedItem("Copy setup command", #selector(copySetupCommand), menu: menu)
        advanced.menu = menu
        cancelButton = button("Cancel request", #selector(discard))
        approveButton = button("Choose project folder…", #selector(primaryAction))
        // Deliberately no default/Return key or shortcut for protected actions.
        approveButton.keyEquivalent = ""
        let spacer = NSView(); spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let actions = NSStackView(views: [advanced, spacer, cancelButton, approveButton]); actions.spacing = 10
        root.addArrangedSubview(actions)
        for view: NSView in [heading, notice, identityLabel, setupForm, summaryScroll, status, actions] { view.widthAnchor.constraint(equalTo: root.widthAnchor, constant: -48).isActive = true }
        home(); refresh(); window.center(); window.makeKeyAndOrderFront(nil)
    }
    private func configureTextView(_ view: NSTextView, label: String, monospaced: Bool) {
        view.isSelectable = true; view.isEditable = false; view.isRichText = false
        view.font = monospaced ? .monospacedSystemFont(ofSize: 12, weight: .regular) : .systemFont(ofSize: 14)
        view.textColor = .textColor; view.backgroundColor = .textBackgroundColor
        view.textContainerInset = NSSize(width: 10, height: 10)
        view.isVerticallyResizable = true; view.isHorizontallyResizable = false
        view.autoresizingMask = [.width]; view.textContainer?.widthTracksTextView = true
        view.setAccessibilityLabel(label)
    }
    private var currentEvent: ValidatedEvent? {
        if case .event(let event, _) = approval.document { return event }; return nil
    }
    private var isReviewing: Bool { request != nil || approval.document != nil || manualEnrollment != nil }
    private var isEnrolling: Bool { request?.operation == .enroll || manualEnrollment != nil }
    private var actionIsArmed: Bool {
        actionArming.isArmed(revision: approval.revision, activeAndKey: NSApp.isActive && window.isKeyWindow, now: ProcessInfo.processInfo.systemUptime)
    }
    private func bindingIsCurrent(_ binding: ApprovalAttemptBinding) -> Bool {
        attempts.isCurrent(binding, revision: approval.revision, identity: identity, connection: connection?.token, requestID: request?.id)
    }
    private func finishWorker(_ binding: ApprovalAttemptBinding) {
        if workerID == binding.attempt { workerID = nil; busy = false }
    }
    private func refresh() {
        guard approveButton != nil else { return }
        actionArming.update(revision: approval.revision, activeAndKey: NSApp.isActive && window.isKeyWindow, now: ProcessInfo.processInfo.systemUptime)
        let free = !busy && !interaction.modalOpen && request == nil && manualEnrollment == nil && !setup.isRunning
        openButton.isEnabled = free; batchButton.isEnabled = free; registryButton.isEnabled = free
        detailsButton.isEnabled = free && currentEvent?.kind == "action.authorization"
        loadButton.isEnabled = free; createButton.isEnabled = listenerReady && free && identity == nil
        exportButton.isEnabled = free && identity != nil
        setupForm.isHidden = isReviewing || setup.isRunning || setupComplete || awaitingNextStep
        chooseButton.isEnabled = free
        humanField.isEnabled = free && identity == nil; projectField.isEnabled = free && identity == nil
        let activeStage = isEnrolling ? SetupStage.identity : approval.document?.setupStage ?? setupStage
        for (index, label) in stepLabels.enumerated() {
            let stage = SetupStage.allCases[index], current = stage == activeStage && !setupComplete
            label.stringValue = "\(index + 1) \(stage.title)" + (current ? " •" : "")
            label.font = .systemFont(ofSize: 12, weight: current ? .bold : .regular)
            label.setAccessibilityLabel(stage.title + (current ? ", current step" : setupComplete ? ", setup complete" : ""))
        }
        cancelButton.isHidden = !isReviewing && !setup.isRunning && !awaitingNextStep
        cancelButton.isEnabled = true
        cancelButton.title = setup.isRunning ? "Stop setup" : awaitingNextStep ? "Back to setup" : "Cancel request"
        if isReviewing {
            var complete = approval.document != nil
            if case .event(let event, let action) = approval.document { complete = event.kind != "action.authorization" || action != nil }
            let title = isEnrolling ? "Create key with Touch ID…" : approval.document?.approvalAction ?? "Approve with Touch ID…"
            approveButton.title = busy ? "Waiting for Touch ID…" : retryAvailable ? "Retry: " + title : title
            approveButton.isEnabled = !busy && !interaction.modalOpen && actionIsArmed && (isEnrolling || (identity != nil && complete))
        } else {
            approveButton.title = setup.isRunning ? "Setup in progress…" : awaitingNextStep ? "Waiting for the CLI…" : setupComplete ? "Check setup" : !folderField.stringValue.hasPrefix("/") ? "Choose project folder…" : setupAttempted || outcome != nil ? "Resume setup" : "Start setup"
            approveButton.isEnabled = listenerReady && !busy && !interaction.modalOpen && !setup.isRunning && !awaitingNextStep
        }
    }
    private func home() {
        heading.stringValue = setupComplete ? "Your local team is ready" : outcome != nil ? outcomeHeading : setup.isRunning ? "Setting up your local team" : "Set up your local team"
        notice.stringValue = "You approve each protected step with fresh Touch ID. Completed steps are kept when setup pauses."
        summary.string = outcome ?? (setupComplete ? "Codex and Claude can now use this project’s local channel.\n\nUse yhes send for agent messages, yhes say to review your own words, and yhes inbox to read messages." : "Identity — create or use this Mac’s signing key.\n\nTeam — check the human and agent identities.\n\nPermissions — choose what the agents may do.\n\nChannel — approve the shared local group.\n\nEach request shows its full scope before you approve it.")
        if !listenerReady { status.stringValue = "This preview cannot sign. Open the provisioned, signed app to start setup." }
        refresh()
    }
    private func invalidate(_ message: String) {
        let wasReviewing = isReviewing || busy
        finishRequest(code: .cancelled)
        backend.cancel(); attempts.cancel(); actionArming.reset(); approval.invalidate(); manualEnrollment = nil; awaitingNextStep = false; retryAvailable = false
        exact.string = ""; exactPanel?.close()
        if wasReviewing || setup.isRunning { outcome = message; outcomeHeading = "Request cancelled" }
        home(); status.stringValue = message; refresh()
    }
    @objc private func discard() {
        if awaitingNextStep && !setup.isRunning && !isReviewing {
            awaitingNextStep = false; home(); status.stringValue = "The previous approval is complete. Choose Resume to check setup progress."; return
        }
        if setup.isRunning { setup.cancel() }
        interrupt(.userCancelled, message: "Request cancelled. No approval was returned. Resume setup when you are ready.")
    }
    @objc private func primaryAction() {
        guard !interaction.modalOpen, !awaitingNextStep || isReviewing else { return }
        if isReviewing { approve() } else if !folderField.stringValue.hasPrefix("/") { chooseFolder() } else { startSetup() }
    }
    private func runManualModal(_ body: () -> NSApplication.ModalResponse) -> NSApplication.ModalResponse? {
        guard interaction.beginModal(revision: approval.revision, hasRequest: request != nil,
                                     hasConnection: connection != nil, busy: busy) else { return nil }
        actionArming.reset(); refresh()
        let response = body()
        let ownsResult = interaction.endModal(revision: approval.revision, hasRequest: request != nil,
                                             hasConnection: connection != nil, busy: busy)
        refresh()
        guard ownsResult else { status.stringValue = "The review changed while the dialog was open. Nothing from that dialog was applied. Open it again to continue."; return nil }
        return response
    }
    private func raiseForReview() {
        actionArming.reset()
        NSApp.activate(ignoringOtherApps: true); window.makeKeyAndOrderFront(nil); refresh()
    }
    private func restoreSetupContext() {
        if let data = UserDefaults.standard.data(forKey: "setupNavigation"),
           let saved = try? JSONDecoder().decode(SetupContext.self, from: data),
           let validated = try? SetupContext(folder: saved.folder, human: saved.human, project: saved.project) {
            setupContext = validated; folderField.stringValue = validated.folder
            humanField.stringValue = validated.human; projectField.stringValue = validated.project
        } else { humanField.stringValue = SetupContext.suggestedID(NSUserName()) }
        refresh()
    }
    private func retainContext(_ context: SetupContext) {
        setupContext = context
        UserDefaults.standard.set(try? JSONEncoder().encode(context), forKey: "setupNavigation")
        folderField.stringValue = context.folder
    }
    func controlTextDidChange(_ notification: Notification) {
        guard !busy, !setup.isRunning, !isReviewing,
              let context = try? SetupContext(folder: folderField.stringValue, human: humanField.stringValue, project: projectField.stringValue) else { return }
        retainContext(context); refresh()
    }
    @objc private func chooseFolder() {
        guard !busy, !setup.isRunning, !isReviewing else { return }
        let panel = NSOpenPanel(); panel.canChooseDirectories = true; panel.canChooseFiles = false
        panel.canCreateDirectories = false; panel.allowsMultipleSelection = false
        panel.message = "Choose the existing project where Codex and Claude will work."
        if let context = setupContext { panel.directoryURL = URL(fileURLWithPath: context.folder) }
        guard runManualModal({ panel.runModal() }) == .OK, let folder = panel.url?.resolvingSymlinksInPath() else { return }
        let human = identity?.author ?? lastRequestContext?.human ?? humanField.stringValue
        let project = identity?.project ?? lastRequestContext?.project ?? SetupContext.suggestedID(folder.lastPathComponent)
        humanField.stringValue = human; projectField.stringValue = project
        do {
            retainContext(try SetupContext(folder: folder.path, human: human, project: project))
            outcome = nil; setupComplete = false; home()
            status.stringValue = "Check the human and project IDs, then start setup. This Mac’s key belongs to one project."
        } catch {
            // Keep the chosen path even if a suggested ID needs correction.
            folderField.stringValue = folder.path; show(error)
        }
        refresh()
    }
    private func startSetup() {
        guard listenerReady, !busy, !setup.isRunning, !isReviewing else { return }
        do {
            let context = try SetupContext(folder: folderField.stringValue, human: humanField.stringValue, project: projectField.stringValue)
            if let identity, identity.author != context.human || identity.project != context.project { throw SignerProtocolError.identityMismatch }
            retainContext(context)
            try setup.start(context) { [weak self] code, stdout, stderr in
                guard let self else { return }
                self.setupTimer?.invalidate(); self.setupTimer = nil
                let result = stdout.result(exitCode: code)
                self.setupComplete = result.succeeded; self.awaitingNextStep = false
                self.outcome = result.message; self.outcomeHeading = result.succeeded ? "Your local team is ready" : "Setup paused"
                if let stage = stderr.progressStage { self.setupStage = stage }
                if !self.isReviewing { self.home(); self.status.stringValue = result.succeeded ? "Setup complete. No approval is retained for future requests." : "Progress is saved. Resume checks completed steps before continuing." }
                self.refresh()
            }
            setupAttempted = true; setupComplete = false; outcome = nil; setupStage = .identity
            home(); status.stringValue = "Starting setup. Review requests will appear here."
            setupTimer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
                MainActor.assumeIsolated {
                    guard let self, !self.isReviewing, self.outcome == nil else { return }
                    if let stage = self.setup.diagnostics.stderr.progressStage {
                        self.setupStage = stage
                        self.status.stringValue = "Preparing \(stage.title.lowercased())… Requests that need your approval will appear here."
                    }
                    self.refresh()
                }
            }
        } catch { outcome = error.localizedDescription; outcomeHeading = "Setup could not start"; home(); show(error) }
    }
    @objc private func showSetupLog() {
        let captured = setup.diagnostics
        let view = NSTextView(); configureTextView(view, label: "Setup diagnostic log", monospaced: true)
        view.string = "Setup output (limited to 32 KiB per stream)\n\n" + captured.stderr.text + "\n\n" + captured.stdout.text
        showTextPanel(view, title: "Setup log")
    }
    private func showTextPanel(_ view: NSTextView, title: String) {
        exactPanel?.close()
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 660, height: 440), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        panel.title = title; panel.isReleasedWhenClosed = false
        let scroll = NSScrollView(frame: panel.contentView!.bounds); scroll.autoresizingMask = [.width, .height]
        scroll.hasVerticalScroller = true; scroll.documentView = view
        panel.contentView!.addSubview(scroll); exactPanel = panel
        panel.center(); panel.makeKeyAndOrderFront(nil)
    }
    @objc private func openDraft() {
        guard !busy, request == nil, !setup.isRunning else { return }
        // Discard the previous review before opening another file, including on error.
        invalidate("Select a draft to review.")
        let panel = NSOpenPanel(); panel.allowedContentTypes = [.json]; panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false; panel.message = "Choose an untrusted event draft. Opening it does not approve it."
        guard runManualModal({ panel.runModal() }) == .OK, let url = panel.url else { return }
        do {
            let bytes = try NativeDraftFile.read(url)
            let event = try ValidatedEvent.parse(bytes)
            approval.replace(with: .event(event, nil))
            displayExactPayloads()
            heading.stringValue = approval.document!.reviewHeading
            summary.string = approval.document!.reviewText
            status.stringValue = event.kind == "action.authorization" ? "Open the exact action details. A request digest alone cannot be approved." : "Agent-prepared draft. Check the exact payload and recipients before approving."
            refresh()
        } catch { show(error) }
    }
    private func displayExactPayloads() {
        switch approval.document {
        case .event(let event, let request):
            exact.string = event.exactText
            if let request { exact.string += "\n\nACTION REQUEST SIDECAR — exact bytes hashed by request_digest:\n" + request.exactText }
        case .statementBatch(let batch):
            exact.string = batch.events.enumerated().map { index, event in
                "STATEMENT \(index + 1) OF \(batch.events.count) — \(event.payload.count) bytes — SHA-256 \(event.digest)\n" + event.exactText
            }.joined(separator: "\n\n")
        case .registry(let registry): exact.string = registry.exactText
        case nil: exact.string = ""
        }
        if let document = approval.document { exact.string = document.reviewDetails + "\n\nEXACT JSON — original reviewed bytes\n\n" + exact.string }
    }
    @objc private func openStatementBatch() {
        guard !busy, request == nil, !setup.isRunning else { return }
        invalidate("Select the complete fixed batch. Nothing selected later can join this approval.")
        let panel = NSOpenPanel(); panel.allowedContentTypes = [.json]; panel.allowsMultipleSelection = true
        panel.canChooseDirectories = false; panel.message = "Select 1–16 human.statement files for one exact batch review."
        guard runManualModal({ panel.runModal() }) == .OK else { return }
        do {
            guard (1...StatementBatch.maxCount).contains(panel.urls.count) else { throw SignerError.invalid("Select 1–16 statement files.") }
            let batch = try StatementBatch(payloads: panel.urls.map(NativeDraftFile.read))
            approval.replace(with: .statementBatch(batch)); displayExactPayloads()
            heading.stringValue = approval.document!.reviewHeading
            summary.string = approval.document!.reviewText
            status.stringValue = "Unapproved batch. Review every statement below. One fresh authentication context applies only to these frozen bytes."
            refresh()
        } catch { show(error) }
    }
    @objc private func openRegistry() {
        guard !busy, request == nil, !setup.isRunning else { return }
        invalidate("Registry mode approves trust bindings. No draft can pin its own authority key.")
        let panel = NSOpenPanel(); panel.allowedContentTypes = [.json]; panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false; panel.message = "Choose a full registry draft. Review every identity, key and revocation."
        guard runManualModal({ panel.runModal() }) == .OK, let url = panel.url else { return }
        do {
            let registry = try ValidatedRegistry.parse(NativeDraftFile.read(url))
            approval.replace(with: .registry(registry)); displayExactPayloads()
            heading.stringValue = approval.document!.reviewHeading
            summary.string = approval.document!.reviewText
            status.stringValue = "Unapproved registry. Verify GHES identity evidence and the current predecessor independently. Receivers must pin this authority key out of band."
            refresh()
        } catch { show(error) }
    }
    @objc private func openActionDetails() {
        guard !busy, request == nil, !setup.isRunning, let event = currentEvent, event.kind == "action.authorization" else { return }
        approval.replace(with: .event(event, nil)); displayExactPayloads(); refresh()
        let panel = NSOpenPanel(); panel.allowedContentTypes = [.json]; panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false; panel.message = "Choose the exact request whose digest is in the authorization."
        guard runManualModal({ panel.runModal() }) == .OK, let url = panel.url else { return }
        do {
            let request = try ActionRequest.parse(NativeDraftFile.read(url))
            try request.validateBinding(to: event)
            approval.replace(with: .event(event, request)); displayExactPayloads()
            summary.string = approval.document!.reviewText
            status.stringValue = "Action: \(request.action) • Performer: \(request.performer). Exact request and all scope bindings match. Review both documents."
            refresh()
        } catch { show(error) }
    }
    private func show(_ error: Error) {
        let reason: String
        switch error as? SignerProtocolError {
        case .identityMissing: reason = "No device key yet. Choose your project folder and start setup."
        case .identityUnavailable: reason = "Keychain is unavailable. Unlock this Mac, then load the identity again."
        case .identityMismatch: reason = "This Mac’s key belongs to a different human or project. Use its existing IDs; keys are never replaced."
        case .cancelled: reason = "The request was cancelled. Resume setup when you are ready."
        default: reason = error.localizedDescription
        }
        status.stringValue = "No approval returned. " + reason; refresh()
    }
    private func useIdentity(_ value: SigningIdentity) {
        identity = value
        identityLabel.stringValue = "Device key: \(value.author) · Project: \(value.project) · This key belongs to one project."
        humanField.stringValue = value.author; projectField.stringValue = value.project
        refresh()
    }
    @objc private func loadIdentity() {
        guard !busy, request == nil, !setup.isRunning else { return }
        invalidate("Loading device identity…")
        identity = nil; identityLabel.stringValue = "No device identity loaded."; refresh()
        do { useIdentity(try backend.load()); status.stringValue = "Device identity loaded. Open a draft to review." }
        catch { show(error) }
    }
    @objc private func createIdentity() {
        guard !busy, request == nil, !setup.isRunning, identity == nil else { return }
        do { try TrustedApplication.requireProtectedIdentity() } catch { show(error); return }
        invalidate("Device setup requires a separate intentional confirmation.")
        let alert = NSAlert(); alert.messageText = "Set up a local human signing key"
        alert.informativeText = "Creates a nonexportable Secure Enclave key protected by the current Touch ID fingerprints. This does not enroll your account in an enterprise registry. Enter the exact author and project IDs from your approved enrollment process."
        let author = NSTextField(); author.placeholderString = "Human ID"; author.stringValue = lastRequestContext?.human ?? humanField.stringValue
        let project = NSTextField(); project.placeholderString = "Project ID"; project.stringValue = lastRequestContext?.project ?? projectField.stringValue
        author.setAccessibilityLabel("Author ID"); project.setAccessibilityLabel("Project ID")
        let form = NSStackView(views: [author, project]); form.orientation = .vertical; form.spacing = 8
        form.frame = NSRect(x: 0, y: 0, width: 440, height: 64); alert.accessoryView = form
        alert.addButton(withTitle: "Cancel"); alert.addButton(withTitle: "Review key setup")
        alert.buttons[1].keyEquivalent = ""
        guard runManualModal({ alert.runModal() }) == .alertSecondButtonReturn else { return }
        let authorID = author.stringValue, projectID = project.stringValue
        guard ValidatedEvent.validID(authorID), ValidatedEvent.validID(projectID) else { show(SignerError.invalid("Enter valid human and project IDs.")); return }
        approval.invalidate(); manualEnrollment = (authorID, projectID); awaitingNextStep = false; outcome = nil
        heading.stringValue = "Set up your signing key"
        notice.stringValue = "Check the human and project below. The next action asks for fresh Touch ID."
        summary.string = "Human ID: \(authorID)\nProject ID: \(projectID)\n\nCreate this Mac’s signing key for this human and project. The private key stays in Secure Enclave and cannot be exported. Existing keys are never replaced."
        status.stringValue = "Review this identity, then choose Create key with Touch ID."
        raiseForReview()
    }
    private func approveManualEnrollment(_ intent: (human: String, project: String)) {
        guard !busy, !interaction.modalOpen, actionIsArmed, request == nil, connection == nil else { return }
        let revision = approval.revision
        do {
            let attempt = try backend.prepareKeySetup(author: intent.human, project: intent.project)
            let binding = ApprovalAttemptBinding(attempt: attempt, connection: nil, requestID: nil, revision: revision, identity: identity)
            attempts.begin(binding); workerID = attempt; busy = true; retryAvailable = false; refresh()
            let backend = backend
            Task {
                do {
                    let value = try await Task.detached { try backend.create(author: intent.human, project: intent.project, attempt: attempt) }.value
                    let current = bindingIsCurrent(binding)
                    useIdentity(value); finishWorker(binding); attempts.finish(binding)
                    if current { manualEnrollment = nil; approval.invalidate(); outcome = "Local key saved. Start or resume setup to review your team and permissions."; outcomeHeading = "Identity saved"; home() }
                    else if !isReviewing { outcome = "The key was saved before cancellation. Resume setup to use it."; outcomeHeading = "Identity saved"; home() }
                    refresh()
                } catch { enrollmentFailed(error, binding: binding) }
            }
        } catch { enrollmentFailed(error, binding: nil) }
    }
    @objc private func approve() {
        guard !busy, !interaction.modalOpen, actionIsArmed else { return }
        if let request, request.operation == .enroll { approveEnrollment(request); return }
        if let manualEnrollment { approveManualEnrollment(manualEnrollment); return }
        guard let identity else { return }
        if connection != nil && !requestIsLive() { invalidate("The CLI disconnected. Resume setup or send the request again."); return }
        let revision = approval.revision, capturedConnection = connection, capturedRequest = request
        do {
            try TrustedApplication.requireProtectedIdentity()
            let document = try approval.checked(revision: revision, identity: identity, now: Int64(Date().timeIntervalSince1970))
            guard ManualReviewGate.ownsDocument(document, requestDocument: capturedRequest?.document, hasRequest: capturedRequest != nil) else {
                throw SignerError.invalid("The displayed document does not belong to the waiting request.")
            }
            let attempt = try backend.prepareReview(document, identity: identity)
            let binding = ApprovalAttemptBinding(attempt: attempt, connection: capturedConnection?.token, requestID: capturedRequest?.id, revision: revision, identity: identity)
            attempts.begin(binding); workerID = attempt; busy = true; retryAvailable = false
            status.stringValue = "Use Touch ID for this exact request. You can cancel in the Touch ID prompt or stop here."; refresh()
            let backend = backend
            Task {
                do {
                    let result = try await Task.detached { try backend.sign(attempt: attempt) }.value
                    guard bindingIsCurrent(binding) else { finishWorker(binding); refresh(); return }
                    let current = try approval.checked(revision: revision, identity: identity, now: Int64(Date().timeIntervalSince1970))
                    guard current == document, result.document == document else { throw SignerError.invalid("The reviewed document changed. Approval was discarded.") }
                    if let capturedConnection { guard pending.token == capturedConnection.token, requestIsLive(), capturedConnection.isLive else { throw SignerProtocolError.cancelled } }
                    let output = try result.exportData()
                    if let capturedRequest, let capturedConnection {
                        guard capturedConnection.respond(try SignerResponse.success(id: capturedRequest.id, result: output)) else { throw SignerProtocolError.cancelled }
                        finishWorker(binding); attempts.finish(binding); detachRequest(); approval.invalidate(); exact.string = ""; exactPanel?.close()
                        awaitingNextStep = document.setupStage != nil
                        outcome = "Approval sent. The waiting CLI continues automatically. Any next step that needs your approval will appear here."; outcomeHeading = "Approval sent"
                        home(); status.stringValue = "This approval is complete. Future requests need a new review and Touch ID."; return
                    }
                    finishWorker(binding); attempts.finish(binding); approval.invalidate(); exact.string = ""; exactPanel?.close()
                    outcome = "The exact reviewed documents were signed. Save the signed output to share it."; outcomeHeading = "Request approved"
                    home(); save(output, suggested: document.suggestedFilename)
                } catch { authenticationFailed(error, binding: binding) }
            }
        } catch {
            actionArming.reset()
            if let current = try? approval.checked(revision: revision, identity: identity, now: Int64(Date().timeIntervalSince1970)),
               ManualReviewGate.ownsDocument(current, requestDocument: capturedRequest?.document, hasRequest: capturedRequest != nil) {
                retryAvailable = true; show(error); raiseForReview()
            } else { invalidate("This request expired, changed or belongs to another review. No approval was returned. Resume setup for a fresh request.") }
        }
    }
    private func enrollmentFailed(_ error: Error, binding: ApprovalAttemptBinding?) {
        if let binding {
            finishWorker(binding)
            guard bindingIsCurrent(binding) else { refresh(); return }
        }
        // The worker has finished. This load is noninteractive and may reveal
        // an identity persisted before delivery, or an already-existing key.
        do {
            let saved = try backend.load()
            if let binding { attempts.finish(binding) }
            finishRequest(code: .identityExists); manualEnrollment = nil; approval.invalidate()
            useIdentity(saved); awaitingNextStep = false; retryAvailable = false
            outcome = "A signing key is already saved for \(saved.author), project \(saved.project). No key was replaced. Resume setup to use this identity."
            outcomeHeading = "Use the saved identity"; home(); status.stringValue = "Key creation has stopped. Resume setup checks the saved identity first."; raiseForReview(); return
        } catch SignerProtocolError.identityMissing {
            // Only authentication failures offer another key-creation attempt.
        } catch {
            pauseEnrollment("The saved key’s status could not be checked. Unlock this Mac, then resume setup to check it again.", binding: binding)
            return
        }
        if case SignerError.invalid(let reason) = error, !reason.contains("Touch ID") {
            pauseEnrollment("Key setup stopped: \(reason) Resume setup to check the saved state before continuing.", binding: binding)
        } else if let protocolError = error as? SignerProtocolError, protocolError != .cancelled {
            pauseEnrollment("Key setup stopped: \(protocolError.localizedDescription) Resume setup to check the identity first.", binding: binding)
        } else if let binding { authenticationFailed(error, binding: binding) }
        else { retryAvailable = true; show(error); raiseForReview() }
    }
    private func pauseEnrollment(_ message: String, binding: ApprovalAttemptBinding?) {
        if let binding { attempts.finish(binding) }
        finishRequest(code: .approvalFailed); backend.cancel(); manualEnrollment = nil; approval.invalidate()
        awaitingNextStep = false; retryAvailable = false
        outcome = message; outcomeHeading = "Key setup paused"; home(); status.stringValue = message; raiseForReview()
    }
    private func authenticationFailed(_ error: Error, binding: ApprovalAttemptBinding) {
        finishWorker(binding)
        guard bindingIsCurrent(binding) else { refresh(); return }
        attempts.finish(binding); actionArming.reset()
        if binding.connection != nil && !requestIsLive() { invalidate("The request ended. No approval was returned. Resume setup to continue."); return }
        if let document = approval.document, let identity {
            do { try document.validate(identity: identity, now: Int64(Date().timeIntervalSince1970)) }
            catch { invalidate("The request expired or is no longer valid. No approval was returned. Resume setup for a fresh request."); return }
        }
        retryAvailable = true
        let failure = error as NSError
        if failure.domain == LAError.errorDomain || failure.domain == NSOSStatusErrorDomain {
            switch failure.code {
            case LAError.userCancel.rawValue, LAError.appCancel.rawValue, LAError.systemCancel.rawValue, Int(errSecUserCanceled):
                status.stringValue = "Touch ID was cancelled. No approval was returned. Review the same request and try again, or cancel it."
            case LAError.biometryLockout.rawValue:
                status.stringValue = "Touch ID is locked. Unlock it on this Mac, then retry this action. No approval was returned."
            case LAError.biometryNotAvailable.rawValue, LAError.biometryNotEnrolled.rawValue:
                status.stringValue = "Touch ID is unavailable. Check Touch ID in System Settings, then try again. No approval was returned."
            default: status.stringValue = "Touch ID did not complete. No approval was returned. Try again or cancel this request."
            }
        } else { status.stringValue = "Approval did not complete: \(error.localizedDescription) Try again or cancel this request." }
        raiseForReview()
    }
    @objc private func exportIdentity() {
        guard !busy, let identity else { return }
        do {
            let data = try JSONSerialization.data(withJSONObject: ["algorithm": DSSE.algorithm,
                "key_id": try identity.keyID, "public_key": identity.publicKey.base64EncodedString(),
                "author": identity.author, "project": identity.project], options: [.sortedKeys])
            save(data, suggested: "public-device-identity.json")
        } catch { show(error) }
    }
    private func save(_ data: Data, suggested: String) {
        let panel = NSSavePanel(); panel.allowedContentTypes = [.json]; panel.nameFieldStringValue = suggested
        guard runManualModal({ panel.runModal() }) == .OK, let url = panel.url else { status.stringValue = "Save cancelled. No file was exported."; return }
        do { try data.write(to: url, options: [.atomic]); status.stringValue = "Saved \(url.lastPathComponent)." }
        catch { show(error) }
    }
}

extension SignerApp {
    private func startLocalService() {
        do {
            try TrustedApplication.requireProtectedIdentity()
            let service = LocalSignerServer(onRequest: { [weak self] connection, request in
                self?.receive(connection, request: request)
            }, onDisconnect: { [weak self] token in
                guard let self, self.pending.token == token else { return }
                self.interrupt(.requestEnded, message: "The CLI disconnected or timed out. No approval was returned. Resume setup when you are ready.")
            })
            try service.start(); server = service; listenerReady = true
            do {
                useIdentity(try backend.load())
                home()
                status.stringValue = "Choose this key’s existing project folder to check or resume setup. CLI requests also appear here."
            } catch SignerProtocolError.identityMissing {
                identityLabel.stringValue = "No device key yet. Your first approval creates it for one human and project."
                status.stringValue = "Choose an existing project folder to begin. No Terminal command is needed."
            } catch {
                identityLabel.stringValue = "Device identity could not be read. Unlock this Mac and choose Load device identity."
                status.stringValue = "Unlock this Mac, then choose Advanced → Reload device identity."
            }
        } catch {
            listenerReady = false
            identityLabel.stringValue = "Local signing is unavailable in this build."
            heading.stringValue = "Finish local app setup"
            summary.string = "Open the provisioned, signed Yhes Signer app to set up a project.\n\nThis preview cannot start setup, read keys or approve requests.\n\nThe signed app will guide you through identity, team, permissions and channel."
            status.stringValue = error as? SignerProtocolError == .busy ? "Another signer is already listening. Use its window, or quit it before reopening." : "No signing service started. The app’s signing identity could not be verified."
        }
        refresh()
    }
    @objc private func copySetupCommand() {
        let helper = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/yhes").path
        let quoted = "'" + helper.replacingOccurrences(of: "'", with: "'\\''") + "'"
        let command = quoted + " pilot --project \"$PWD\" --human YOUR_ID"
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(command, forType: .string)
        status.stringValue = "Setup command copied. Paste it in your project folder and replace YOUR_ID with your human ID."
    }
    @objc private func toggleDetails() { showTextPanel(exact, title: "Review details — keys and exact JSON") }
    private func identityData(_ value: SigningIdentity) throws -> Data {
        try JSONSerialization.data(withJSONObject: ["algorithm": DSSE.algorithm, "key_id": try value.keyID,
            "public_key": value.publicKey.base64EncodedString(), "author": value.author, "project": value.project], options: [.sortedKeys])
    }
    private func requestIsLive() -> Bool {
        guard let connection else { return false }
        return pending.isCurrent(connection.token, now: ProcessInfo.processInfo.systemUptime) && connection.isLive
    }
    private func detachRequest() {
        if let connection { _ = pending.finish(connection.token) }
        connection = nil; request = nil
    }
    private func finishRequest(code: SignerProtocolError) {
        if let connection, let request {
            _ = connection.respond(SignerResponse.failure(id: request.id, code: code))
        }
        detachRequest()
    }
    private func receive(_ incoming: LocalSignerConnection, request value: SignerRequest) {
        guard incoming.isLive else { return }
        guard interaction.canReceive(hasReview: approval.document != nil || manualEnrollment != nil, hasRequest: request != nil, hasConnection: connection != nil, busy: busy) else { incoming.fail(.busy); return }
        do {
            switch value.operation {
            case .identity:
                let valueIdentity = try backend.load()
                try value.requireIdentity(valueIdentity)
                useIdentity(valueIdentity)
                _ = incoming.respond(try SignerResponse.success(id: value.id, result: identityData(valueIdentity)))
                return
            case .enroll:
                do {
                    _ = try backend.load()
                    incoming.fail(.identityExists); return
                } catch SignerProtocolError.identityMissing { /* explicit setup below */ }
            case .review:
                let valueIdentity = try backend.load()
                try value.requireIdentity(valueIdentity)
                guard let document = value.document else { throw SignerProtocolError.invalidDocument }
                try document.validate(identity: valueIdentity, now: Int64(Date().timeIntervalSince1970))
                useIdentity(valueIdentity)
            }
            try pending.begin(token: incoming.token, now: ProcessInfo.processInfo.systemUptime)
            approval.invalidate(); actionArming.reset()
            connection = incoming; request = value; retryAvailable = false
            lastRequestContext = (value.author, value.project); outcome = nil; setupComplete = false; awaitingNextStep = false
            if identity == nil { humanField.stringValue = value.author; projectField.stringValue = value.project }
            if let document = value.document {
                if let stage = document.setupStage { setupStage = stage }
                approval.replace(with: document)
                heading.stringValue = document.reviewHeading
                summary.string = document.reviewText
                displayExactPayloads()
                status.stringValue = "Review the full scope and recipients above, then choose the action below. Touch ID confirms only this request."
                notice.stringValue = "Unapproved request from the signed local CLI. Approval applies only to the text, scope and recipients shown here."
            } else {
                heading.stringValue = "Set up your signing key"
                summary.string = "Human ID: \(value.author)\nProject ID: \(value.project)\n\nCreate this Mac’s signing key for this human and project. The private key stays in Secure Enclave and cannot be exported. This key can be used only for this project.\n\nOnly your public identity is returned. Next you will review the team and its permissions. Existing keys are never replaced."
                exact.string = ""
                notice.stringValue = "Key setup requested by the signed local CLI. Check the author and project before continuing."
                status.stringValue = "CLI is waiting for key setup. Cancel to return without creating a key."
            }
            refresh()
            NSApp.activate(ignoringOtherApps: true); window.makeKeyAndOrderFront(nil)
        } catch {
            incoming.fail(error as? SignerProtocolError ?? .invalidDocument)
        }
    }
    private func approveEnrollment(_ request: SignerRequest) {
        guard !busy, actionIsArmed, requestIsLive(), let capturedConnection = connection else { return }
        let revision = approval.revision
        do {
            let attempt = try backend.prepareKeySetup(author: request.author, project: request.project)
            let binding = ApprovalAttemptBinding(attempt: attempt, connection: capturedConnection.token, requestID: request.id, revision: revision, identity: identity)
            attempts.begin(binding); workerID = attempt; busy = true; retryAvailable = false
            status.stringValue = "Use Touch ID to create the key for the human and project shown above."; refresh()
            let backend = backend
            Task {
                do {
                    let value = try await Task.detached { try backend.create(author: request.author, project: request.project, attempt: attempt) }.value
                    let current = bindingIsCurrent(binding)
                    // create() returns only after add-only persistence. Retain the
                    // real identity even if the caller disconnected meanwhile.
                    useIdentity(value)
                    guard current, pending.token == capturedConnection.token, requestIsLive(), capturedConnection.isLive,
                          value.author == request.author, value.project == request.project else {
                        finishWorker(binding); attempts.finish(binding)
                        if current { invalidate("The key was created, but the request ended before delivery. Resume setup to use the saved key.") }
                        else if !isReviewing { outcome = "The key was created before cancellation. No approval was returned. Resume setup to use the saved key."; outcomeHeading = "Identity saved"; home() }
                        refresh(); return
                    }
                    guard let response = try? SignerResponse.success(id: request.id, result: identityData(value)), capturedConnection.respond(response) else {
                        finishWorker(binding); attempts.finish(binding)
                        invalidate("The key was saved, but its public identity could not be delivered. Resume setup to continue."); return
                    }
                    finishWorker(binding); attempts.finish(binding); detachRequest()
                    awaitingNextStep = true
                    outcome = "Identity sent. Only the public identity was returned. The CLI continues with the team review; its next request will appear here."; outcomeHeading = "Identity ready"; setupStage = .team
                    home(); status.stringValue = "Identity complete. The CLI continues automatically."
                } catch { enrollmentFailed(error, binding: binding) }
            }
        } catch { enrollmentFailed(error, binding: nil) }
    }
}
