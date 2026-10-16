package com.aricummings.enclave;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.graphics.ImageFormat;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.hardware.camera2.CaptureRequest;
import android.hardware.camera2.params.OutputConfiguration;
import android.hardware.camera2.params.SessionConfiguration;
import android.media.Image;
import android.media.ImageReader;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.PersistableBundle;
import android.provider.OpenableColumns;
import android.view.WindowManager;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;

/**
 * The app's activity: Android's NativeActivity running libenclave_mobile.so
 * (nym/enclave-mobile), plus what only Java can reach. The Rust side
 * (enclave_platform::phone::android) calls the public methods here through
 * JNI and gets answers through the native methods, which it registers when
 * the library starts. Each method is small and does no app logic.
 */
public class EnclaveActivity extends android.app.NativeActivity {
    private static final int SAVE_BASE = 1 << 20;
    private static final int PERMISSION_CAMERA = 1;
    private static final int PERMISSION_NOTIFY = 2;
    private static final int PERMISSION_MICROPHONE = 3;
    private static final String CHANNEL = "messages";
    /** How long a copied text stays on the clipboard. */
    private static final long CLIPBOARD_MS = 60_000;

    private final Handler main = new Handler(Looper.getMainLooper());
    private byte[] pendingSave;

    static native void nativePicked(int request, String[] paths);
    static native void nativeSaved(int request, boolean ok, String where);
    static native void nativeFrame(byte[] grey, int width, int height);
    static native void nativeColorFrame(byte[] i420, int width, int height, int rotation);
    static native void nativeScanFailed(String why);
    static native void nativeScreenFrame(byte[] rgba, int width, int height);
    static native void nativeScreenFailed(String why);

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        // Screen security: no screenshots, no recording, a blank thumbnail
        // in the app switcher (docs/14-storage.md §5); on until the
        // profile's setting says otherwise (setSecure).
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                        != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[] {Manifest.permission.POST_NOTIFICATIONS}, PERMISSION_NOTIFY);
        }
        EnclaveService.windowOpen = true;
        // Staying connected (the default) keeps the vault running once the
        // window closes; with a push service, wakes start it.
        if (EnclaveService.delivery(this) == 0) {
            EnclaveService.start(this);
        }
        if (EnclaveService.delivery(this) == Native.FCM) {
            Fcm.start(this);
        }
        callIntent(getIntent());
        linkIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        callIntent(intent);
        linkIntent(intent);
    }

    /** Opened by a tapped enclave: link: it goes to the Add screen. */
    private void linkIntent(Intent intent) {
        if (intent == null || !Intent.ACTION_VIEW.equals(intent.getAction()) || intent.getData() == null) {
            return;
        }
        Native.event(Native.OPEN_LINK, intent.getData().toString());
        intent.setData(null);
    }

    /** Opened by a ringing call's notification: over the lock screen, answering if asked. */
    private void callIntent(Intent intent) {
        String call = intent == null ? null : intent.getStringExtra(Calls.EXTRA);
        if (call == null) {
            return;
        }
        intent.removeExtra(Calls.EXTRA);
        setShowWhenLocked(true);
        setTurnScreenOn(true);
        if ("answer".equals(call)) {
            Calls.answer();
        }
    }

    // Calls -----------------------------------------------------------------

    /** The call's state for the system's call handling (Calls.report). */
    public void callState(int state, String name, boolean video) {
        Calls.report(this, state, name, video);
        if (state == Calls.ENDED) {
            main.post(() -> {
                setShowWhenLocked(false);
                setTurnScreenOn(false);
            });
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        Native.event(Native.VISIBLE, "1");
    }

    @Override
    protected void onPause() {
        Native.event(Native.VISIBLE, "0");
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        Native.event(Native.ACTIVITY_GONE, "");
        EnclaveService.windowOpen = false;
        super.onDestroy();
    }

    // How messages arrive with the app closed ---------------------------------

    /** 0 stay connected, 1 UnifiedPush, 3 Google's push. */
    public int delivery() {
        return EnclaveService.delivery(this);
    }

    /** Whether Android may stop the service to save battery (PC-22). */
    public boolean batteryRestricted() {
        android.os.PowerManager pm = getSystemService(android.os.PowerManager.class);
        return pm != null && !pm.isIgnoringBatteryOptimizations(getPackageName());
    }

    /** Android's own list of battery optimisation, where Enclave can be let run. */
    public void openBatterySettings() {
        try {
            startActivity(new Intent(android.provider.Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS));
        } catch (android.content.ActivityNotFoundException e) {
            startActivity(new Intent(android.provider.Settings.ACTION_SETTINGS));
        }
    }

    /** The ways this phone offers, as bits (1 << way). */
    public int deliveryChoices() {
        int ways = 1;
        if (!UnifiedPush.distributors(this).isEmpty()) {
            ways |= 1 << Native.UNIFIEDPUSH;
        }
        if (Fcm.available()) {
            ways |= 1 << Native.FCM;
        }
        return ways;
    }

    /** Use `way` from now on; reported back through Native.event. */
    public void setDelivery(int way) {
        runOnUiThread(() -> {
            int was = EnclaveService.delivery(this);
            if (way == was) {
                return;
            }
            if (was == Native.UNIFIEDPUSH) {
                UnifiedPush.stop(this);
            } else if (was == Native.FCM) {
                Fcm.stop(this);
            }
            if (way == Native.UNIFIEDPUSH) {
                // Its link screen answers in onActivityResult.
                UnifiedPush.link(this);
                return;
            }
            EnclaveService.prefs(this).edit().putInt(EnclaveService.DELIVERY, way).apply();
            if (way == Native.FCM) {
                Fcm.start(this);
            } else {
                EnclaveService.start(this);
            }
            Native.event(Native.DELIVERY, Integer.toString(way));
        });
    }

    /** The system's font size (1.0 is the default). */
    public float fontScale() {
        return getResources().getConfiguration().fontScale;
    }

    /** Animations are off in the system's settings. */
    public boolean reduceMotion() {
        return android.provider.Settings.Global.getFloat(
                getContentResolver(), android.provider.Settings.Global.ANIMATOR_DURATION_SCALE, 1f) == 0f;
    }

    /** Screen security on or off (Settings → Hide from screenshots). */
    public void setSecure(boolean on) {
        runOnUiThread(() -> {
            if (on) {
                getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
            } else {
                getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
            }
        });
    }

    // File pickers ----------------------------------------------------------

    /** Ask for files of `mime` (one, or several); answers nativePicked. */
    public void pick(int request, String mime, boolean several) {
        runOnUiThread(() -> {
            Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType(mime);
            i.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, several);
            try {
                startActivityForResult(i, request);
            } catch (Exception e) {
                nativePicked(request, new String[0]);
            }
        });
    }

    /** Ask where to save `bytes` as `name`; answers nativeSaved. */
    public void save(int request, String name, byte[] bytes) {
        runOnUiThread(() -> {
            pendingSave = bytes;
            Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType("application/octet-stream");
            i.putExtra(Intent.EXTRA_TITLE, name);
            try {
                startActivityForResult(i, SAVE_BASE + request);
            } catch (Exception e) {
                pendingSave = null;
                nativeSaved(request, false, e.toString());
            }
        });
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == Screen.REQUEST) {
            Screen.granted(this, result, data);
            return;
        }
        if (request == UnifiedPush.LINK_REQUEST) {
            UnifiedPush.linked(this, result, data);
            Native.event(Native.DELIVERY, Integer.toString(EnclaveService.delivery(this)));
            return;
        }
        if (request >= SAVE_BASE) {
            int id = request - SAVE_BASE;
            byte[] bytes = pendingSave;
            pendingSave = null;
            Uri uri = (result == RESULT_OK && data != null) ? data.getData() : null;
            if (uri == null || bytes == null) {
                nativeSaved(id, false, "");
                return;
            }
            new Thread(() -> {
                try (OutputStream out = getContentResolver().openOutputStream(uri)) {
                    out.write(bytes);
                    nativeSaved(id, true, displayName(uri));
                } catch (Exception e) {
                    nativeSaved(id, false, e.toString());
                }
            }).start();
            return;
        }
        ArrayList<Uri> uris = new ArrayList<>();
        if (result == RESULT_OK && data != null) {
            if (data.getClipData() != null) {
                for (int k = 0; k < data.getClipData().getItemCount(); k++) {
                    uris.add(data.getClipData().getItemAt(k).getUri());
                }
            } else if (data.getData() != null) {
                uris.add(data.getData());
            }
        }
        // Copied into the app's cache, where the app reads them by path.
        new Thread(() -> {
            File dir = new File(getCacheDir(), "picked");
            dir.mkdirs();
            ArrayList<String> paths = new ArrayList<>();
            for (Uri uri : uris) {
                File f = new File(dir, System.nanoTime() + "-" + safe(displayName(uri)));
                try (InputStream in = getContentResolver().openInputStream(uri);
                        OutputStream out = new FileOutputStream(f)) {
                    byte[] buf = new byte[65536];
                    for (int n; (n = in.read(buf)) > 0; ) {
                        out.write(buf, 0, n);
                    }
                    paths.add(f.getAbsolutePath());
                } catch (Exception e) {
                    f.delete();
                }
            }
            nativePicked(request, paths.toArray(new String[0]));
        }).start();
    }

    private String displayName(Uri uri) {
        try (Cursor c = getContentResolver().query(uri, new String[] {OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (c != null && c.moveToFirst()) {
                return c.getString(0);
            }
        } catch (Exception e) {
            // Fall through to the URI's last part.
        }
        String last = uri.getLastPathSegment();
        return last == null ? "file" : last;
    }

    private static String safe(String name) {
        String n = name.replaceAll("[^A-Za-z0-9._ -]", "_");
        return n.startsWith(".") || n.isEmpty() ? "file" : n;
    }

    // Notifications ---------------------------------------------------------

    /** Show a notification unless the app is in front. */
    public void notify(String title, String body) {
        if (hasWindowFocus()) {
            return;
        }
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm.getNotificationChannel(CHANNEL) == null) {
            nm.createNotificationChannel(new NotificationChannel(CHANNEL, "Messages", NotificationManager.IMPORTANCE_HIGH));
        }
        Intent open = new Intent(this, EnclaveActivity.class).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent tap = PendingIntent.getActivity(this, 0, open, PendingIntent.FLAG_IMMUTABLE);
        Notification n = new Notification.Builder(this, CHANNEL)
                .setSmallIcon(getApplicationInfo().icon)
                .setContentTitle(title)
                .setContentText(body)
                .setContentIntent(tap)
                .setAutoCancel(true)
                .setVisibility(Notification.VISIBILITY_PRIVATE)
                .build();
        nm.notify(1, n);
    }

    // Clipboard -------------------------------------------------------------

    /** Copy `text`, marked sensitive, and clear it after a minute if it is still there. */
    public boolean copy(String text) {
        ClipboardManager cb = getSystemService(ClipboardManager.class);
        if (cb == null) {
            return false;
        }
        ClipData clip = ClipData.newPlainText("Enclave", text);
        PersistableBundle extras = new PersistableBundle();
        extras.putBoolean(Build.VERSION.SDK_INT >= 33 ? ClipDescription.EXTRA_IS_SENSITIVE : "android.content.extra.IS_SENSITIVE", true);
        clip.getDescription().setExtras(extras);
        main.post(() -> cb.setPrimaryClip(clip));
        main.postDelayed(() -> {
            ClipData now = cb.getPrimaryClip();
            if (now != null && now.getItemCount() > 0 && text.contentEquals(String.valueOf(now.getItemAt(0).getText()))) {
                cb.clearPrimaryClip();
            }
        }, CLIPBOARD_MS);
        return true;
    }

    // Camera (scanning codes) -----------------------------------------------

    private HandlerThread cameraThread;
    private CameraDevice camera;
    private CameraCaptureSession session;
    private ImageReader reader;
    private long lastFrame;
    /** The camera is for a video call (front, colour), not a scan. */
    private boolean callCamera;

    /** Ask for the microphone when a call starts; the call's audio keeps
     *  trying to open it, so the answer needs no reply. */
    public void askMicrophone() {
        runOnUiThread(() -> {
            if (checkSelfPermission(Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[] {Manifest.permission.RECORD_AUDIO}, PERMISSION_MICROPHONE);
            }
        });
    }

    /** Share the screen in a video call (Android asks first); pictures go to
     *  nativeScreenFrame. */
    public void startScreenShare() {
        runOnUiThread(() -> Screen.ask(this));
    }

    /** Stop sharing the screen. */
    public void stopScreenShare() {
        Screen.stop(this, true);
    }

    /** Start the front camera for a video call; colour frames go to
     *  nativeColorFrame. */
    public void startCallCamera() {
        runOnUiThread(() -> {
            callCamera = true;
            if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[] {Manifest.permission.CAMERA}, PERMISSION_CAMERA);
                return;
            }
            openCamera();
        });
    }

    /** Start the back camera; frames go to nativeFrame as brightness only. */
    public void startScan() {
        runOnUiThread(() -> {
            callCamera = false;
            if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[] {Manifest.permission.CAMERA}, PERMISSION_CAMERA);
                return;
            }
            openCamera();
        });
    }

    @Override
    public void onRequestPermissionsResult(int request, String[] permissions, int[] results) {
        super.onRequestPermissionsResult(request, permissions, results);
        if (request == PERMISSION_CAMERA) {
            if (results.length > 0 && results[0] == PackageManager.PERMISSION_GRANTED) {
                openCamera();
            } else {
                nativeScanFailed("Enclave may not use the camera. Allow it in Settings → Apps → Enclave → Permissions.");
            }
        }
    }

    private void openCamera() {
        try {
            CameraManager cm = getSystemService(CameraManager.class);
            final boolean call = callCamera;
            final int wanted = call ? CameraCharacteristics.LENS_FACING_FRONT : CameraCharacteristics.LENS_FACING_BACK;
            String id = null;
            for (String c : cm.getCameraIdList()) {
                Integer facing = cm.getCameraCharacteristics(c).get(CameraCharacteristics.LENS_FACING);
                if (facing != null && facing == wanted) {
                    id = c;
                    break;
                }
            }
            if (id == null && cm.getCameraIdList().length > 0) {
                id = cm.getCameraIdList()[0];
            }
            if (id == null) {
                nativeScanFailed("No camera was found.");
                return;
            }
            cameraThread = new HandlerThread("enclave-camera");
            cameraThread.start();
            Handler h = new Handler(cameraThread.getLooper());
            Integer sensor = cm.getCameraCharacteristics(id).get(CameraCharacteristics.SENSOR_ORIENTATION);
            final int rotation = sensor == null ? 0 : sensor;
            reader = ImageReader.newInstance(640, 480, ImageFormat.YUV_420_888, 2);
            reader.setOnImageAvailableListener(r -> {
                Image img = r.acquireLatestImage();
                if (img == null) {
                    return;
                }
                try {
                    long now = System.currentTimeMillis();
                    if (now - lastFrame < (call ? 66 : 120)) {
                        return;
                    }
                    lastFrame = now;
                    if (call) {
                        nativeColorFrame(i420(img), img.getWidth(), img.getHeight(), rotation);
                        return;
                    }
                    Image.Plane y = img.getPlanes()[0];
                    int w = img.getWidth(), ht = img.getHeight();
                    ByteBuffer buf = y.getBuffer();
                    int stride = y.getRowStride();
                    byte[] grey = new byte[w * ht];
                    for (int row = 0; row < ht; row++) {
                        buf.position(row * stride);
                        buf.get(grey, row * w, Math.min(w, buf.remaining()));
                    }
                    nativeFrame(grey, w, ht);
                } finally {
                    img.close();
                }
            }, h);
            cm.openCamera(id, new CameraDevice.StateCallback() {
                @Override
                public void onOpened(CameraDevice d) {
                    camera = d;
                    try {
                        CaptureRequest.Builder b = d.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW);
                        b.addTarget(reader.getSurface());
                        b.set(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE);
                        d.createCaptureSession(new SessionConfiguration(SessionConfiguration.SESSION_REGULAR,
                                Collections.singletonList(new OutputConfiguration(reader.getSurface())), h::post,
                                new CameraCaptureSession.StateCallback() {
                            @Override
                            public void onConfigured(CameraCaptureSession s) {
                                session = s;
                                try {
                                    s.setRepeatingRequest(b.build(), null, h);
                                } catch (Exception e) {
                                    nativeScanFailed("The camera can't be started.");
                                }
                            }

                            @Override
                            public void onConfigureFailed(CameraCaptureSession s) {
                                nativeScanFailed("The camera can't be started.");
                            }
                        }));
                    } catch (Exception e) {
                        nativeScanFailed("The camera can't be started.");
                    }
                }

                @Override
                public void onDisconnected(CameraDevice d) {
                    d.close();
                }

                @Override
                public void onError(CameraDevice d, int error) {
                    d.close();
                    nativeScanFailed("The camera is busy or can't be opened.");
                }
            }, h);
        } catch (SecurityException e) {
            nativeScanFailed("Enclave may not use the camera.");
        } catch (Exception e) {
            nativeScanFailed("The camera is busy or can't be opened.");
        }
    }

    /** I420 from a YUV_420_888 image, whatever its strides. */
    private static byte[] i420(Image img) {
        int w = img.getWidth(), h = img.getHeight();
        int cw = (w + 1) / 2, ch = (h + 1) / 2;
        byte[] out = new byte[w * h + 2 * cw * ch];
        Image.Plane[] p = img.getPlanes();
        int at = 0;
        for (int i = 0; i < 3; i++) {
            ByteBuffer b = p[i].getBuffer();
            int rs = p[i].getRowStride(), ps = p[i].getPixelStride();
            int pw = i == 0 ? w : cw, ph = i == 0 ? h : ch;
            for (int y = 0; y < ph; y++) {
                for (int x = 0; x < pw; x++) {
                    int idx = y * rs + x * ps;
                    out[at++] = idx < b.limit() ? b.get(idx) : 0;
                }
            }
        }
        return out;
    }

    /** Turn the camera off. */
    public void stopScan() {
        runOnUiThread(() -> {
            if (session != null) {
                session.close();
                session = null;
            }
            if (camera != null) {
                camera.close();
                camera = null;
            }
            if (reader != null) {
                reader.close();
                reader = null;
            }
            if (cameraThread != null) {
                cameraThread.quitSafely();
                cameraThread = null;
            }
        });
    }

    // Keystore --------------------------------------------------------------

    /** Keep `secret` under `account`, sealed to a key in the Android Keystore. */
    /** A helper in its own process (HelperService.start). */
    public int startHelper(String name, String[] args) {
        return HelperService.start(this, name, args);
    }

    public boolean keySet(String account, byte[] secret) {
        return Keys.set(this, account, secret);
    }

    /** The secret under `account`, or null. */
    public byte[] keyGet(String account) {
        return Keys.get(this, account);
    }

    /** Delete the secret under `account` and its key. */
    public boolean keyDelete(String account) {
        return Keys.delete(this, account);
    }

    /** Every account kept whose name starts with `prefix`. */
    public String[] keyList(String prefix) {
        return Keys.list(this, prefix);
    }

    /** Whether the Android Keystore answers. */
    public boolean keyAvailable() {
        return Keys.available();
    }
}
