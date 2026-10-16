package com.aricummings.enclave;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.graphics.PixelFormat;
import android.hardware.display.DisplayManager;
import android.hardware.display.VirtualDisplay;
import android.media.Image;
import android.media.ImageReader;
import android.media.projection.MediaProjection;
import android.media.projection.MediaProjectionManager;
import android.os.Handler;
import android.os.HandlerThread;
import java.nio.ByteBuffer;

/**
 * Sharing the screen in a video call (docs/11-calls.md §8.3): Android asks
 * first (MediaProjection), and shows that the screen is being recorded.
 * The screen, mirrored into a 960 × 540 picture, goes five times a second
 * to EnclaveActivity.nativeScreenFrame. Android 14 lets the projection
 * start only once a foreground service of its kind runs, so the grant goes
 * to EnclaveService, which starts it.
 */
final class Screen {
    static final int REQUEST = 7301;
    private static final int WIDTH = 960, HEIGHT = 540;
    private static final long GAP_MS = 200;

    private static MediaProjection projection;
    private static VirtualDisplay display;
    private static ImageReader reader;
    private static HandlerThread thread;
    private static long last;

    private Screen() {}

    /** Ask to record the screen; the answer comes to granted(). */
    static void ask(Activity a) {
        MediaProjectionManager m = a.getSystemService(MediaProjectionManager.class);
        a.startActivityForResult(m.createScreenCaptureIntent(), REQUEST);
    }

    /** The system's answer. */
    static void granted(Activity a, int result, Intent data) {
        if (result != Activity.RESULT_OK || data == null) {
            EnclaveActivity.nativeScreenFailed("Screen sharing wasn't allowed.");
            return;
        }
        EnclaveService.project(a, result, data);
    }

    /** Called by EnclaveService once it runs as a media projection service. */
    static synchronized void begin(Context c, int result, Intent data) {
        stop(c, false);
        try {
            MediaProjectionManager m = c.getSystemService(MediaProjectionManager.class);
            projection = m.getMediaProjection(result, data);
            if (projection == null) {
                EnclaveActivity.nativeScreenFailed("Screen sharing couldn't start.");
                return;
            }
            thread = new HandlerThread("enclave-screen");
            thread.start();
            Handler h = new Handler(thread.getLooper());
            projection.registerCallback(new MediaProjection.Callback() {
                @Override
                public void onStop() {
                    // Stopped from the system's own controls.
                    EnclaveActivity.nativeScreenFailed("");
                    stop(c, true);
                }
            }, h);
            reader = ImageReader.newInstance(WIDTH, HEIGHT, PixelFormat.RGBA_8888, 2);
            reader.setOnImageAvailableListener(r -> {
                Image img = r.acquireLatestImage();
                if (img == null) {
                    return;
                }
                try {
                    long now = System.currentTimeMillis();
                    if (now - last < GAP_MS) {
                        return;
                    }
                    last = now;
                    Image.Plane p = img.getPlanes()[0];
                    ByteBuffer buf = p.getBuffer();
                    int rs = p.getRowStride(), ps = p.getPixelStride();
                    int w = img.getWidth(), ht = img.getHeight();
                    byte[] out = new byte[w * ht * 4];
                    if (ps == 4) {
                        for (int y = 0; y < ht; y++) {
                            buf.position(y * rs);
                            buf.get(out, y * w * 4, w * 4);
                        }
                    }
                    EnclaveActivity.nativeScreenFrame(out, w, ht);
                } finally {
                    img.close();
                }
            }, h);
            int dpi = c.getResources().getDisplayMetrics().densityDpi;
            display = projection.createVirtualDisplay("Enclave screen share", WIDTH, HEIGHT, dpi,
                    DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR, reader.getSurface(), null, h);
        } catch (RuntimeException e) {
            EnclaveActivity.nativeScreenFailed("Screen sharing couldn't start.");
            stop(c, true);
        }
    }

    /** Stop sharing (the call's controls, or the call ended). */
    static synchronized void stop(Context c, boolean service) {
        if (display != null) {
            display.release();
            display = null;
        }
        if (projection != null) {
            projection.stop();
            projection = null;
        }
        if (reader != null) {
            reader.close();
            reader = null;
        }
        if (thread != null) {
            thread.quitSafely();
            thread = null;
        }
        if (service) {
            EnclaveService.project(c, 0, null);
        }
    }
}
