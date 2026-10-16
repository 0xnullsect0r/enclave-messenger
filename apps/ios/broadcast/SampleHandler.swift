// Enclave's broadcast upload extension (docs/11-calls.md §8.3): sharing the
// screen in a video call. iOS starts it from the system's broadcast picker
// (the app shows it), records the whole screen and hands each frame here.
// Five a second, fitted into 960 × 540, go to the app through a file in the
// app group's container that only the app and this extension can read:
//
//   "ENSC" ‖ u32 sequence ‖ u32 width ‖ u32 height ‖ BGRA rows, top first
//
// The app ends the broadcast by leaving a `screen.stop` file. Nothing else
// is kept, and nothing leaves the device from here: the app encrypts and
// sends the pictures as its call's video.
import CoreImage
import CoreMedia
import ReplayKit

class SampleHandler: RPBroadcastSampleHandler {
    private let width = 960
    private let height = 540
    private let dir = FileManager.default.containerURL(
        forSecurityApplicationGroupIdentifier: "group.com.aricummings.enclave")
    private let context = CIContext()
    private var last = Date.distantPast
    private var sequence: UInt32 = 0

    private func file(_ name: String) -> URL? {
        dir?.appendingPathComponent(name)
    }

    private func state(_ s: String) {
        if let f = file("screen.state") {
            try? Data(s.utf8).write(to: f, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        }
    }

    override func broadcastStarted(withSetupInfo setupInfo: [String: NSObject]?) {
        if let stop = file("screen.stop") {
            try? FileManager.default.removeItem(at: stop)
        }
        state("on")
    }

    override func broadcastFinished() {
        state("off")
        if let f = file("screen.frame") {
            try? FileManager.default.removeItem(at: f)
        }
    }

    override func processSampleBuffer(_ sample: CMSampleBuffer, with type: RPSampleBufferType) {
        guard type == .video, let out = file("screen.frame"), let stop = file("screen.stop") else {
            return
        }
        if FileManager.default.fileExists(atPath: stop.path) {
            try? FileManager.default.removeItem(at: stop)
            finishBroadcastWithError(NSError(
                domain: "com.aricummings.enclave", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Screen sharing ended in Enclave."]))
            return
        }
        let now = Date()
        if now.timeIntervalSince(last) < 0.2 {
            return
        }
        last = now
        guard let pixels = CMSampleBufferGetImageBuffer(sample) else {
            return
        }
        var image = CIImage(cvPixelBuffer: pixels)
        if let o = CMGetAttachment(sample, key: RPVideoSampleOrientationKey as CFString,
                                   attachmentModeOut: nil) as? NSNumber,
           let orientation = CGImagePropertyOrientation(rawValue: o.uint32Value) {
            image = image.oriented(orientation)
        }
        // Fit (letterboxed), then flip: Core Image counts rows from the
        // bottom, the file from the top.
        let w = CGFloat(width), h = CGFloat(height)
        let e = image.extent
        let s = min(w / e.width, h / e.height)
        let scaled = image.transformed(by: CGAffineTransform(scaleX: s, y: s))
        let placed = scaled.transformed(by: CGAffineTransform(
            translationX: (w - scaled.extent.width) / 2 - scaled.extent.minX,
            y: (h - scaled.extent.height) / 2 - scaled.extent.minY))
        let frame = CGRect(x: 0, y: 0, width: w, height: h)
        let picture = placed
            .composited(over: CIImage(color: CIColor.black).cropped(to: frame))
            .transformed(by: CGAffineTransform(scaleX: 1, y: -1).translatedBy(x: 0, y: -h))
        sequence &+= 1
        var bytes = Data(count: 16 + width * height * 4)
        bytes.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return }
            raw.storeBytes(of: 0x4353_4E45 as UInt32, toByteOffset: 0, as: UInt32.self)
            raw.storeBytes(of: sequence.littleEndian, toByteOffset: 4, as: UInt32.self)
            raw.storeBytes(of: UInt32(width).littleEndian, toByteOffset: 8, as: UInt32.self)
            raw.storeBytes(of: UInt32(height).littleEndian, toByteOffset: 12, as: UInt32.self)
            context.render(picture, toBitmap: base + 16, rowBytes: width * 4, bounds: frame,
                           format: .BGRA8, colorSpace: CGColorSpaceCreateDeviceRGB())
        }
        try? bytes.write(to: out, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }
}
