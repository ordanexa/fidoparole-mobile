import SwiftUI

struct PassphraseSheet: View {
    let title: String
    let repeatField: Bool
    let hint: String
    var mergeOption: Binding<Bool>? = nil
    var onOK: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var a = ""
    @State private var b = ""

    private var problem: String? {
        if repeatField && !a.isEmpty && a.count < 10 { return "Use at least 10 characters." }
        if repeatField && !b.isEmpty && a != b { return "The passphrases differ." }
        return nil
    }

    var body: some View {
        NavigationStack {
            Form {
                Section { Text(hint).font(.footnote) }
                Section {
                    SecureField("Passphrase", text: $a)
                    if repeatField { SecureField("Repeat passphrase", text: $b) }
                    if let p = problem { Text(p).foregroundStyle(.red).font(.footnote) }
                }
                if let merge = mergeOption {
                    Section {
                        Picker("Mode", selection: merge) {
                            Text("Merge (newest copy of each entry wins)").tag(false)
                            Text("Replace this vault").tag(true)
                        }.pickerStyle(.inline).labelsHidden()
                    }
                }
            }
            .navigationTitle(title)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Continue") { let p = a; dismiss(); onOK(p) }
                        .disabled(a.isEmpty || problem != nil || (repeatField && a != b))
                }
            }
        }
    }
}

struct CopySheet: View {
    @EnvironmentObject var model: VaultModel
    @Environment(\.dismiss) private var dismiss
    let defaultName: String
    @State private var name = ""
    @State private var pin = ""

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("1. Have the target key at hand.\n2. Enter its PIN and the vault name, then tap Copy.\n3. Hold the target key to the iPhone until FidoParole says it's done: the vault credential is created and the entries are written, encrypted with that key's own secret.")
                        .font(.footnote)
                }
                Section {
                    TextField("Vault name", text: $name)
                    SecureField("Target key PIN", text: $pin).keyboardType(.numberPad)
                }
            }
            .navigationTitle("Copy to another key")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Copy") { let p = pin, n = name; dismiss(); Task { await model.copyToOtherKey(pin: p, name: n) } }
                        .disabled(pin.isEmpty || name.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
            .onAppear { name = defaultName }
        }
    }
}

struct DeleteSheet: View {
    @EnvironmentObject var model: VaultModel
    @Environment(\.dismiss) private var dismiss
    let name: String
    let count: Int
    let dirty: Bool
    @State private var ack = false
    @State private var typed = ""
    private var expected: String { name.isEmpty ? "DELETE" : name }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("This permanently erases “\(name)” (\(count) \(count == 1 ? "entry" : "entries")) from the key: the encrypted data and the vault credential. It takes effect immediately and cannot be undone.")
                        .foregroundStyle(.red)
                    Text("Copies on other keys and backup files are not affected. Without one of those, nobody can recover these passwords.").font(.footnote)
                    if dirty { Text("There are unsaved changes.").bold() }
                }
                Section {
                    Toggle("I have a backup or a copy, or I accept losing these passwords", isOn: $ack)
                    TextField("Type \(expected) to confirm", text: $typed).textInputAutocapitalization(.never).autocorrectionDisabled()
                }
            }
            .navigationTitle("Delete vault?")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .destructiveAction) {
                    Button("Delete", role: .destructive) { dismiss(); Task { await model.deleteVault() } }
                        .disabled(!ack || typed.trimmingCharacters(in: .whitespaces) != expected)
                }
            }
        }
    }
}
