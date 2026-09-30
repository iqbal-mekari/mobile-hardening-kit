import MobileHardeningKit
import SwiftUI

struct ContentView: View {
  @StateObject private var model = HardeningModel()
  @Environment(\.scenePhase) private var scenePhase

  var body: some View {
    NavigationView {
      List {
        Section {
          Button("Scan now") { model.scan() }
          Toggle("Screen protection (app-switcher blur)", isOn: $model.screenProtection)
        }
        Section(header: Text("Snapshot")) {
          if model.snapshot.isEmpty {
            Text("No signals observed (not proof of integrity).")
          }
          ForEach(Array(model.snapshot.enumerated()), id: \.offset) { row(for: $0.element) }
        }
        Section(header: Text("Events")) {
          if model.events.isEmpty {
            Text("Waiting for capture/display events...")
          }
          ForEach(Array(model.events.enumerated()), id: \.offset) { row(for: $0.element) }
        }
      }
      .navigationTitle("Hardening Kit Sample")
    }
    .navigationViewStyle(.stack)
    .onAppear {
      model.scan()
      model.startObserving()
    }
    .onDisappear { model.stopObserving() }
    .onChange(of: scenePhase) { phase in
      if phase == .active { model.scan() }
    }
  }

  private func row(for signal: HardeningSignal) -> some View {
    VStack(alignment: .leading, spacing: 4) {
      Text(signal.type.rawValue).font(.headline)
      Text(signal.observedAt.description).font(.caption)
      Text(verbatim: "\(signal.metadata)").font(.caption).foregroundColor(.secondary)
    }
  }
}
