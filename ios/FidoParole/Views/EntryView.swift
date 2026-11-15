import SwiftUI

struct EntryView: View {
    @EnvironmentObject var model: VaultModel
    let id: String
    @State private var generating = false
    @State private var confirmDelete = false
    @Environment(\.dismiss) private var dismiss

    private func binding(_ field: EntryField, _ get: @escaping (EntryDetails) -> String) -> Binding<String> {
        Binding(get: { model.entry.map(get) ?? "" }, set: { model.update(field, $0) })
    }

    var body: some View {
        Form {
            if let e = model.entry {
                Section {
                    TextField("Title", text: binding(.title) { $0.title })
                    HStack {
                        TextField("Username", text: binding(.username) { $0.username }).textInputAutocapitalization(.never).autocorrectionDisabled()
                        Button { model.copy(.username) } label: { Image(systemName: "doc.on.doc") }.buttonStyle(.borderless)
                    }
                    HStack {
                        if let pw = model.revealed {
                            TextField("Password", text: Binding(get: { pw }, set: { model.update(.password, $0) }))
                                .font(.body.monospaced()).textInputAutocapitalization(.never).autocorrectionDisabled()
                        } else {
                            Text(e.hasPassword ? "••••••••••••" : "No password").foregroundStyle(e.hasPassword ? .primary : .secondary)
                            Spacer()
                        }
                        Button { model.toggleReveal() } label: { Image(systemName: model.revealed == nil ? "eye" : "eye.slash") }.buttonStyle(.borderless)
                        Button { model.copy(.password) } label: { Image(systemName: "doc.on.doc") }.buttonStyle(.borderless)
                    }
                    Button { generating = true } label: { Label("Generate password", systemImage: "dice") }
                    HStack {
                        TextField("URL", text: binding(.url) { $0.url }).keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                        Button { model.copy(.url) } label: { Image(systemName: "doc.on.doc") }.buttonStyle(.borderless)
                    }
                }
                Section("Notes") {
                    TextField("Notes", text: binding(.notes) { $0.notes }, axis: .vertical).lineLimit(3...8)
                }
                Section {
                    Text("Modified \(Date(timeIntervalSince1970: TimeInterval(e.modified)).formatted(date: .abbreviated, time: .shortened))")
                        .font(.footnote).foregroundStyle(.secondary)
                    if model.status?.dirty == true { Button("Save to key") { Task { await model.save() } } }
                    Button("Delete entry", role: .destructive) { confirmDelete = true }
                }
            }
        }
        .navigationTitle(model.entry?.title ?? "Entry")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { model.openEntry(id) }
        .onDisappear { if model.entry?.id == id { model.closeEntry() } }
        .sheet(isPresented: $generating) { GeneratorSheet { model.generate($0) } }
        .confirmationDialog("Delete this entry?", isPresented: $confirmDelete, titleVisibility: .visible) {
            Button("Delete", role: .destructive) { model.deleteEntry(); dismiss() }
        } message: { Text("It is removed from the vault when you next save to the key.") }
    }
}

struct GeneratorSheet: View {
    var onGenerate: (GenOptions) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var length = 20.0
    @State private var upper = true, lower = true, digits = true, symbols = true

    var body: some View {
        NavigationStack {
            Form {
                Section("Length: \(Int(length))") { Slider(value: $length, in: 8...64, step: 1) }
                Section {
                    Toggle("A–Z", isOn: $upper); Toggle("a–z", isOn: $lower)
                    Toggle("0–9", isOn: $digits); Toggle("Symbols", isOn: $symbols)
                }
            }
            .navigationTitle("Generate password")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Generate") {
                        onGenerate(GenOptions(length: UInt32(length), upper: upper, lower: lower, digits: digits, symbols: symbols)); dismiss()
                    }.disabled(!(upper || lower || digits || symbols))
                }
            }
        }
        .presentationDetents([.medium])
    }
}
