import SwiftUI
import UniformTypeIdentifiers

struct BackupFile: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }
    var data: Data
    init(data: Data) { self.data = data }
    init(configuration: ReadConfiguration) throws { data = configuration.file.regularFileContents ?? Data() }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper { FileWrapper(regularFileWithContents: data) }
}

struct VaultView: View {
    @EnvironmentObject var model: VaultModel
    @State private var sheet: Sheet?
    @State private var exportFile: BackupFile?
    @State private var importing = false
    @State private var importPass = ""
    @State private var importReplace = false

    enum Sheet: String, Identifiable { case copy, export, importPass, delete; var id: String { rawValue } }

    var body: some View {
        let st = model.status
        List {
            if let st, st.max > 0 {
                Section {
                    VStack(alignment: .leading, spacing: 4) {
                        ProgressView(value: Double(st.used), total: Double(st.max)).tint(Double(st.used) / Double(st.max) > 0.9 ? .red : .green)
                        Text("Key storage: \(st.used) / \(st.max) bytes").font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            if st?.dirty == true {
                Section {
                    HStack {
                        Text("Unsaved changes — only in memory until you save them to the key.").font(.footnote)
                        Spacer()
                        Button("Save") { Task { await model.save() } }.buttonStyle(.borderedProminent)
                    }
                }.listRowBackground(Color.yellow.opacity(0.15))
            }
            Section {
                if model.entries.isEmpty {
                    Text(model.query.isEmpty ? "No entries yet. Tap + to add one." : "No matches.").foregroundStyle(.secondary)
                }
                ForEach(model.entries, id: \.id) { e in
                    NavigationLink(value: e.id) {
                        HStack(spacing: 12) {
                            Text(String(e.title.prefix(1)).uppercased())
                                .font(.headline).foregroundStyle(Color.brand)
                                .frame(width: 34, height: 34).background(Color.brand.opacity(0.12), in: Circle())
                            VStack(alignment: .leading) {
                                Text(e.title.isEmpty ? "(untitled)" : e.title)
                                Text(e.username.isEmpty ? e.url : e.username).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                            }
                        }
                    }
                }
            }
        }
        .searchable(text: $model.query)
        .navigationTitle(st?.name ?? "Vault")
        .navigationDestination(for: String.self) { id in EntryView(id: id) }
        .toolbar {
            ToolbarItem(placement: .navigationBarLeading) { Button { model.lock() } label: { Image(systemName: "lock.fill") } }
            ToolbarItemGroup(placement: .navigationBarTrailing) {
                Button { model.addEntry() } label: { Image(systemName: "plus") }
                Menu {
                    Button("Save to key") { Task { await model.save() } }
                    Button("Copy vault to another key…") { sheet = .copy }
                    Button("Export encrypted backup…") { sheet = .export }
                    Button("Import backup…") { sheet = .importPass }
                    Divider()
                    Button("Delete vault from key…", role: .destructive) { sheet = .delete }
                } label: { Image(systemName: "ellipsis.circle") }
            }
        }
        .sheet(item: $sheet) { s in
            switch s {
            case .copy: CopySheet(defaultName: st?.name ?? "")
            case .export: PassphraseSheet(title: "Export encrypted backup", repeatField: true,
                    hint: "The file is protected by this passphrase (Argon2id + AES-256-GCM) and opens without any security key — keep file and passphrase apart.") { pass in
                    Task { if let d = await model.exportBackup(passphrase: pass) { exportFile = BackupFile(data: d) } }
                }
            case .importPass: PassphraseSheet(title: "Import backup", repeatField: false, hint: "Enter the backup's passphrase, then pick the .t2vault file.", mergeOption: $importReplace) { pass in
                    importPass = pass; importing = true
                }
            case .delete: DeleteSheet(name: st?.name ?? "", count: Int(st?.entryCount ?? 0), dirty: st?.dirty == true)
            }
        }
        .fileExporter(isPresented: Binding(get: { exportFile != nil }, set: { if !$0 { exportFile = nil } }),
                      document: exportFile, contentType: .data, defaultFilename: "\(st?.name ?? "vault").t2vault") { result in
            if case .success = result { model.message = "Backup saved" }
        }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.data]) { result in
            guard case .success(let url) = result else { return }
            let ok = url.startAccessingSecurityScopedResource()
            defer { if ok { url.stopAccessingSecurityScopedResource() } }
            guard let data = try? Data(contentsOf: url) else { model.error = "Could not read the backup file"; return }
            let pass = importPass; importPass = ""
            Task { await model.importBackup(data, passphrase: pass, replace: importReplace) }
        }
    }
}
