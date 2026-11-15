import Foundation
import SwiftUI
import UIKit
import UniformTypeIdentifiers

/// How the key is reached. iOS gives apps no access to USB FIDO keys, so
/// it's NFC — or the built-in demo key.
enum KeyRoute { case nfc, demo }

struct BusyState: Equatable {
    var text: String
    var touch = false
}

@MainActor
final class VaultModel: ObservableObject {
    @Published var busy: BusyState?
    @Published var message: String?
    @Published var error: String?
    @Published var choices: [(name: String, session: VaultSession)]?
    @Published var status: VaultStatus?
    @Published var entries: [EntrySummary] = []
    @Published var query = "" { didSet { refresh() } }
    @Published var entry: EntryDetails?
    @Published var revealed: String?

    private var session: VaultSession?
    private var route: KeyRoute = .nfc
    private var demoLink: KeyLink?
    private var backgroundSince: Date?
    private let reader = NFCKeyReader()

    var nfcAvailable: Bool { NFCKeyReader.available }
    var isOpen: Bool { session != nil }

    private final class Touch: KeyListener, @unchecked Sendable {
        weak var model: VaultModel?
        init(_ m: VaultModel) { model = m }
        func touchNeeded() { Task { @MainActor [weak self] in self?.model?.busy?.touch = true } }
    }
    private lazy var listener = Touch(self)

    // MARK: key operations

    /// Run `body` with a link to the key off the main thread.
    private func withKey<T: Sendable>(_ text: String, route: KeyRoute, _ body: @escaping @Sendable (KeyLink) throws -> T) async -> T? {
        busy = BusyState(text: text)
        error = nil
        defer { busy = nil }
        let listener = self.listener
        do {
            switch route {
            case .nfc:
                return try await reader.run(prompt: "Hold your key to the top of the iPhone. \(text)", listener: listener, body)
            case .demo:
                let link: KeyLink
                if let l = demoLink { link = l } else { link = try KeyLink.demo(listener: listener); demoLink = link }
                return try await Task.detached { try body(link) }.value
            }
        } catch is CancellationError {
            return nil
        } catch {
            self.error = describe(error)
            return nil
        }
    }

    private func offMain<T: Sendable>(_ text: String, _ body: @escaping @Sendable () throws -> T) async -> T? {
        busy = BusyState(text: text)
        defer { busy = nil }
        do { return try await Task.detached { try body() }.value }
        catch { self.error = describe(error); return nil }
    }

    func unlock(pin: String) async {
        guard !pin.isEmpty else { error = "Enter the key's PIN"; return }
        if let vaults = await withKey("Unlocking…", route: .nfc, { link in try FidoParole.unlock(link: link, pin: pin) }) {
            route = .nfc
            if vaults.count == 1 { open(vaults[0]) } else { choices = vaults.map { ((try? $0.status().name) ?? "Vault", $0) } }
        }
    }

    func startDemo() async {
        if let vaults = await withKey("Opening the demo vault…", route: .demo, { link in try FidoParole.unlock(link: link, pin: demoPin()) }) {
            route = .demo
            open(vaults[0])
            message = "Demo mode: a software key inside the app. Nothing is stored anywhere."
        }
    }

    func create(name: String, pin: String) async {
        let name = name.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty else { error = "Give the vault a name"; return }
        guard !pin.isEmpty else { error = "Enter the key's PIN"; return }
        if let v = await withKey("Creating the vault…", route: .nfc, { link in try createVault(link: link, pin: pin, name: name) }) {
            route = .nfc
            open(v)
            message = "Vault created on the key"
        }
    }

    func choose(_ index: Int) {
        guard let c = choices else { return }
        for (i, item) in c.enumerated() where i != index { item.session.lock() }
        open(c[index].session)
    }

    func cancelChoose() { choices?.forEach { $0.session.lock() }; choices = nil }

    private func open(_ v: VaultSession) {
        session = v
        choices = nil
        query = ""
        entry = nil
        revealed = nil
        refresh()
        if let s = status { message = s.notice ?? s.problem }
    }

    func refresh() {
        guard let v = session else { return }
        status = try? v.status()
        entries = (try? v.entries(query: query)) ?? []
    }

    func save() async {
        guard let v = session else { return }
        let nfc = route == .nfc
        let ok: Bool? = await withKey("Saving to the key…", route: route) { link in
            // Over NFC each tap could be another key: check it's this vault's and unchanged.
            if nfc, try v.reconnect(link: link) { return false }
            _ = try v.save(link: link)
            return true
        }
        refresh()
        if ok == true { message = "Saved to the key" }
        if ok == false { error = "The vault on this key changed since you opened it (saved from another device). Lock and unlock to see it, or save again to overwrite it." }
    }

    func copyToOtherKey(pin: String, name: String) async {
        guard let v = session else { return }
        guard !pin.isEmpty else { error = "Enter the target key's PIN"; return }
        let ok: Void? = await withKey("Copying the vault to this key…", route: .nfc) { link in
            try v.copyToKey(target: link, pin: pin, name: name)
        }
        if ok != nil { message = "The vault is now also on that key. The copies are independent." }
    }

    func deleteVault() async {
        guard let v = session else { return }
        let ok: Void? = await withKey("Removing the vault from the key…", route: route) { link in try v.deleteFromKey(link: link) }
        if ok != nil { lock(); message = "Vault deleted from the key" }
    }

    // MARK: entries

    private func guarded(_ f: () throws -> Void) {
        do { try f() } catch { self.error = describe(error) }
    }

    func openEntry(_ id: String) { guarded { entry = try session?.entry(id: id); revealed = nil } }
    func closeEntry() { entry = nil; revealed = nil; refresh() }

    func addEntry() {
        guarded {
            guard let id = try session?.addEntry(title: "New entry") else { return }
            refresh()
            openEntry(id)
        }
    }

    func update(_ field: EntryField, _ value: String) {
        guard let v = session, let id = entry?.id else { return }
        guarded {
            try v.updateEntry(id: id, field: field, value: value)
            entry = try v.entry(id: id)
            if field == .password { revealed = value }
            status = try v.status()
        }
    }

    func deleteEntry() {
        guard let id = entry?.id else { return }
        guarded { try session?.deleteEntry(id: id) }
        closeEntry()
    }

    func toggleReveal() {
        guard let id = entry?.id else { return }
        guarded { revealed = revealed == nil ? try session?.password(id: id) : nil }
    }

    func generate(_ opts: GenOptions) {
        guard let v = session, let id = entry?.id else { return }
        guarded {
            try v.generatePassword(id: id, opts: opts)
            entry = try v.entry(id: id)
            revealed = try v.password(id: id)
            status = try v.status()
            message = "New password generated"
        }
    }

    func copy(_ field: EntryField) {
        guard let v = session, let e = entry else { return }
        guarded {
            let text: String
            switch field {
            case .password: text = try v.password(id: e.id)
            case .username: text = e.username
            case .url: text = e.url
            default: return
            }
            guard !text.isEmpty else { return }
            // Local only (no Universal Clipboard), cleared after 30 s.
            UIPasteboard.general.setItems([[UTType.plainText.identifier: text]],
                                          options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(30)])
            message = "Copied — the clipboard clears in 30 s"
        }
    }

    // MARK: backups

    func exportBackup(passphrase: String) async -> Data? {
        guard let v = session else { return nil }
        return await offMain("Encrypting the backup…") { try v.exportBackup(passphrase: passphrase) }
    }

    func importBackup(_ data: Data, passphrase: String, replace: Bool) async {
        guard let v = session else { return }
        if let msg = await offMain("Decrypting the backup…", { try v.importBackup(file: data, passphrase: passphrase, replace: replace) }) {
            refresh()
            message = msg + " Save to the key to keep it."
        }
    }

    // MARK: locking

    func lock() {
        session?.lock()
        session = nil
        status = nil
        entries = []
        entry = nil
        revealed = nil
        choices = nil
    }

    func didEnterBackground() { backgroundSince = Date() }

    /// Auto-lock: 2 minutes away, 8 with unsaved changes.
    func didBecomeActive() {
        defer { backgroundSince = nil }
        guard let since = backgroundSince, session != nil else { return }
        let dirty = status?.dirty == true
        if Date().timeIntervalSince(since) > (dirty ? 480 : 120) {
            lock()
            message = dirty ? "Locked after inactivity — unsaved changes were discarded" : "Locked after inactivity"
        }
    }
}
