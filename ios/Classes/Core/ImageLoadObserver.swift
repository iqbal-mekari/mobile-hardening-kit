import Darwin
import Foundation
import MachO

/// Image-path fragments of known injection frameworks, matched case-insensitively.
enum InjectionNeedles {
  static let all: [StaticString] = [
    "frida", "fridagadget", "mobilesubstrate", "cydiasubstrate", "substitute", "libhooker",
    "ellekit", "xposed",
  ]

  /// True when `path` contains a needle. Allocation-free, so it is safe inside dyld callbacks.
  static func matches(_ path: UnsafePointer<CChar>) -> Bool {
    for needle in all {
      let fragment = UnsafeRawPointer(needle.utf8Start).assumingMemoryBound(to: CChar.self)
      if strcasestr(path, fragment) != nil { return true }
    }
    return false
  }

  /// The bounded artifact form of a matching path, shared by image scans and load events.
  static func artifact(_ path: String) -> String {
    String(path.lowercased().suffix(120))
  }
}

/// A matching image reported by the add-image callback.
struct ImageLoad: Equatable {
  /// Artifact form of the image path (`InjectionNeedles.artifact`).
  let path: String
  /// False for images replayed while the callback registers; those belong to the `start` pass.
  let live: Bool
}

/// A live image-load registration; `cancel()` ends delivery and is idempotent.
protocol ImageLoadObservation: AnyObject {
  func cancel()
}

/// Process-wide `_dyld_register_func_for_add_image` registration.
///
/// dyld has no unregister API, so the callback is registered at most once per process, on a
/// background queue because dyld replays every loaded image synchronously on the registering
/// thread. The callback runs under dyld's loader lock: it reads only the lock-protected flags,
/// runs `dladdr` and the C-string needle match, copies matching paths, and enqueues them on
/// `queue`. Subscribers are looked up on `queue` and called on the main queue, never inside the
/// callback.
final class DyldImageLoadObserver {
  static let shared = DyldImageLoadObserver()

  /// Callback-visible state, guarded by `lock`.
  struct Flags {
    /// At least one subscriber is attached; otherwise the callback returns before `dladdr`.
    var enabled = false
    var registrationStarted = false
    /// False until the registration call returns: earlier callbacks are its replay.
    var live = false
    var callbacks = 0
    var replayedImages = 0
    /// `_dyld_image_count()` right after the registration call returned.
    var imagesAtRegistration = 0
  }

  private struct Entry {
    let id: ObjectIdentifier
    weak var subscription: Subscription?
  }

  private let lock: UnsafeMutablePointer<os_unfair_lock>
  private let flags: UnsafeMutablePointer<Flags>
  private var entries: [Entry] = []  // guarded by `lock`
  private var pending: [ImageLoad] = []  // confined to `queue`
  /// Serial queue that owns `pending`; hits are converted and batched here.
  let queue = DispatchQueue(label: "com.mekari.mobile_hardening_kit.image-loads")
  private let registration = DispatchGroup()

  private init() {
    lock = .allocate(capacity: 1)
    lock.initialize(to: os_unfair_lock())
    flags = .allocate(capacity: 1)
    flags.initialize(to: Flags())
  }

  /// Delivers matching image loads to `onLoad` on the main queue until the observation is
  /// cancelled. The first call registers the dyld callback.
  func observe(_ onLoad: @escaping ([ImageLoad]) -> Void) -> ImageLoadObservation {
    let subscription = Subscription(observer: self, onLoad: onLoad)
    os_unfair_lock_lock(lock)
    entries.append(Entry(id: ObjectIdentifier(subscription), subscription: subscription))
    flags.pointee.enabled = true
    let register = !flags.pointee.registrationStarted
    flags.pointee.registrationStarted = true
    os_unfair_lock_unlock(lock)
    if register {
      registration.enter()
      DispatchQueue.global(qos: .utility).async { [self] in
        _dyld_register_func_for_add_image(dyldImageAdded)
        let images = Int(_dyld_image_count())
        os_unfair_lock_lock(lock)
        flags.pointee.live = true
        flags.pointee.replayedImages = flags.pointee.callbacks
        flags.pointee.imagesAtRegistration = images
        os_unfair_lock_unlock(lock)
        registration.leave()
      }
    }
    return subscription
  }

  /// Waits until the one-time registration (and its replay) has returned.
  func waitForRegistration(timeout: TimeInterval) -> Bool {
    registration.wait(timeout: .now() + timeout) == .success
  }

  /// A consistent copy of the callback-visible state.
  var state: Flags {
    os_unfair_lock_lock(lock)
    defer { os_unfair_lock_unlock(lock) }
    return flags.pointee
  }

  /// The dyld callback body. Runs under the loader lock on the loading (or registering) thread.
  fileprivate func imageAdded(_ header: UnsafePointer<mach_header>) {
    os_unfair_lock_lock(lock)
    flags.pointee.callbacks += 1
    let enabled = flags.pointee.enabled
    let live = flags.pointee.live
    os_unfair_lock_unlock(lock)
    var info = Dl_info()
    guard enabled, dladdr(header, &info) != 0, let path = info.dli_fname else { return }
    imagePathAdded(path, live: live)
  }

  /// Matches `path` and, on a hit, copies it (bounded) and enqueues it for delivery.
  func imagePathAdded(_ path: UnsafePointer<CChar>, live: Bool) {
    guard InjectionNeedles.matches(path), let copy = strndup(path, Int(PATH_MAX)) else { return }
    queue.async { self.enqueue(copy, live: live) }
  }

  private func enqueue(_ path: UnsafeMutablePointer<CChar>, live: Bool) {
    pending.append(ImageLoad(path: InjectionNeedles.artifact(String(cString: path)), live: live))
    free(path)
    if pending.count == 1 { queue.async(execute: flush) }
  }

  /// Hands the batch to every subscriber on the main queue; weak references load off the lock.
  private func flush() {
    let loads = pending
    pending.removeAll()
    os_unfair_lock_lock(lock)
    let entries = self.entries
    os_unfair_lock_unlock(lock)
    let subscriptions = entries.compactMap(\.subscription)
    guard !subscriptions.isEmpty else { return }
    DispatchQueue.main.async {
      for subscription in subscriptions { subscription.deliver(loads) }
    }
  }

  fileprivate func remove(_ id: ObjectIdentifier) {
    os_unfair_lock_lock(lock)
    entries.removeAll { $0.id == id }
    flags.pointee.enabled = !entries.isEmpty
    os_unfair_lock_unlock(lock)
  }

  private final class Subscription: ImageLoadObservation {
    private let observer: DyldImageLoadObserver
    private var onLoad: (([ImageLoad]) -> Void)?

    init(observer: DyldImageLoadObserver, onLoad: @escaping ([ImageLoad]) -> Void) {
      self.observer = observer
      self.onLoad = onLoad
    }

    deinit {
      observer.remove(ObjectIdentifier(self))
    }

    /// Main queue only.
    func deliver(_ loads: [ImageLoad]) {
      onLoad?(loads)
    }

    /// Main queue only.
    func cancel() {
      onLoad = nil
      observer.remove(ObjectIdentifier(self))
    }
  }
}

/// Registered once; reads only process-global state.
private let dyldImageAdded: @convention(c) (UnsafePointer<mach_header>?, Int) -> Void = {
  header, _ in
  guard let header else { return }
  DyldImageLoadObserver.shared.imageAdded(header)
}
