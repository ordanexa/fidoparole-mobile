import SwiftUI

@main
struct FidoParoleApp: App {
    @StateObject private var model = VaultModel()
    @Environment(\.scenePhase) private var phase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
                .tint(.brand)
                // Hide the vault in the app switcher.
                .overlay { if phase != .active && model.isOpen { PrivacyCover() } }
        }
        .onChange(of: phase) { p in
            if p == .background { model.didEnterBackground() }
            if p == .active { model.didBecomeActive() }
        }
    }
}

extension Color {
    static let brand = Color(red: 0.949, green: 0.188, blue: 0.345)
}

struct PrivacyCover: View {
    var body: some View {
        ZStack {
            Color(.systemBackground).ignoresSafeArea()
            Label("FidoParole", systemImage: "lock.fill").font(.title2.bold()).foregroundStyle(Color.brand)
        }
    }
}

struct RootView: View {
    @EnvironmentObject var model: VaultModel

    var body: some View {
        ZStack {
            if model.status != nil {
                NavigationStack { VaultView() }
            } else if model.choices != nil {
                NavigationStack { ChooseView() }
            } else {
                NavigationStack { StartView() }
            }
            if let b = model.busy { BusyView(state: b) }
        }
        .alert("Couldn't complete that", isPresented: Binding(get: { model.error != nil }, set: { if !$0 { model.error = nil } })) {
            Button("OK", role: .cancel) {}
        } message: { Text(model.error ?? "") }
        .overlay(alignment: .bottom) {
            if let m = model.message {
                Text(m).font(.callout).padding(.horizontal, 16).padding(.vertical, 10)
                    .background(.thinMaterial, in: Capsule()).padding(.bottom, 24)
                    .task(id: m) { try? await Task.sleep(nanoseconds: 3_500_000_000); if model.message == m { model.message = nil } }
            }
        }
    }
}

struct BusyView: View {
    let state: BusyState
    var body: some View {
        ZStack {
            Color.black.opacity(0.25).ignoresSafeArea()
            VStack(spacing: 14) {
                Image(systemName: "touchid").font(.system(size: 40)).foregroundStyle(Color.brand)
                    .frame(width: 72, height: 72).background(Color.brand.opacity(0.12), in: Circle())
                if state.touch { Text("Touch the key now").font(.caption.bold()).padding(6).background(Color.brand.opacity(0.12), in: Capsule()) }
                Text(state.text).multilineTextAlignment(.center).font(.body.weight(.medium))
                ProgressView()
            }
            .padding(24).frame(maxWidth: 320).background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16))
        }
    }
}
