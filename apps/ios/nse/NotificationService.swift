// Enclave's notification service extension (docs/10-push.md §5.1). A push
// says only "New message"; with previews on, its capsule (`c`) opens with
// the notification keys the app shares (crates/enclave-nse), and the
// notification shows who wrote and the start of the message. Nothing is
// written to disk, and nothing else is done here.
import UserNotifications

@_silgen_name("enclave_nse_open")
func enclaveNseOpen(_ capsule: UnsafePointer<UInt8>?, _ len: Int,
                    _ out: UnsafeMutablePointer<UInt8>?, _ outLen: Int) -> Int

class NotificationService: UNNotificationServiceExtension {
    override func didReceive(_ request: UNNotificationRequest,
                             withContentHandler done: @escaping (UNNotificationContent) -> Void) {
        guard let content = request.content.mutableCopy() as? UNMutableNotificationContent else {
            done(request.content)
            return
        }
        if let c = request.content.userInfo["c"] as? String,
           let capsule = Data(base64Encoded: c) {
            var out = [UInt8](repeating: 0, count: 1024)
            let n = capsule.withUnsafeBytes { raw in
                out.withUnsafeMutableBufferPointer { buf in
                    enclaveNseOpen(raw.bindMemory(to: UInt8.self).baseAddress, capsule.count,
                                   buf.baseAddress, buf.count)
                }
            }
            if n > 0, let text = String(bytes: out[0..<n], encoding: .utf8) {
                let parts = text.split(separator: "\0", maxSplits: 1,
                                       omittingEmptySubsequences: false)
                if parts.count == 2 {
                    content.title = String(parts[0])
                    content.body = String(parts[1])
                }
            }
            out.withUnsafeMutableBufferPointer { buf in
                for i in buf.indices { buf[i] = 0 }
            }
        }
        done(content)
    }

    // Everything is done at once in didReceive; nothing to cut short.
    override func serviceExtensionTimeWillExpire() {}
}
