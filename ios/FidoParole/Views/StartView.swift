import SwiftUI

struct StartView: View {
    @EnvironmentObject var model: VaultModel
    @State private var pin = ""
    @State private var newName = "Personal"
    @State private var showCreate = false

    var body: some View {
        Form {
            Section {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Your passwords, on your key").font(.title2.bold())
                    Text("The vault is encrypted with a secret only your FIDO2 key can produce, stored on the key itself, and decrypted in memory only.")
                        .font(.subheadline).foregroundStyle(.secondary)
                }.padding(.vertical, 6)
            }
            Section {
                SecureField("Key PIN", text: $pin).keyboardType(.numberPad).textContentType(.oneTimeCode)
                Button {
                    let p = pin; pin = ""
                    Task { await model.unlock(pin: p) }
                } label: { Label("Unlock with NFC", systemImage: "wave.3.right") }
                .disabled(!model.nfcAvailable)
            } header: { Text("Security key") } footer: {
                Text(model.nfcAvailable
                     ? "Hold your key to the top of the iPhone when asked, and keep it there until FidoParole says it's done. iOS does not let apps use FIDO keys over USB, so NFC is used."
                     : "This device can't read NFC tags.")
            }
            Section {
                DisclosureGroup("Create a new vault on the key", isExpanded: $showCreate) {
                    TextField("Vault name", text: $newName).onChange(of: newName) { v in
                        if v.utf8.count > Int(maxVaultNameBytes()) { newName = String(v.prefix(32)) }
                    }
                    Button("Create vault") {
                        let p = pin; pin = ""
                        Task { await model.create(name: newName, pin: p) }
                    }
                    Text("Uses the PIN above. Keep the key on the phone while the vault credential is created and the empty vault is written.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
            Section {
                Button { Task { await model.startDemo() } } label: { Label("No key at hand? Try the demo", systemImage: "testtube.2") }
            }
        }
        .navigationTitle("FidoParole")
    }
}

struct ChooseView: View {
    @EnvironmentObject var model: VaultModel
    var body: some View {
        List {
            ForEach(Array((model.choices ?? []).enumerated()), id: \.offset) { i, c in
                Button { model.choose(i) } label: { Label(c.name, systemImage: "lock.fill") }
            }
        }
        .navigationTitle("Choose a vault")
        .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { model.cancelChoose() } } }
    }
}
