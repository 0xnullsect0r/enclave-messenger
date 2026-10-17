package com.aricummings.enclave;

/**
 * Calls into libenclave_mobile.so (nym/enclave-mobile) that don't need the
 * activity: starting the vault without a window, and events (in front or
 * not, push tokens, wakes).
 */
final class Native {
    static final int VISIBLE = 1;
    static final int PUSH_TOKEN = 2;
    static final int WAKE = 3;
    static final int ACTIVITY_GONE = 4;
    static final int DELIVERY = 5;
    /** The system's call screen: "answer", "end", "mute:1" or "mute:0". */
    static final int CALL = 6;
    static final int OPEN_LINK = 7;
    static final int OPEN_FAILED = 8;
    /** A location, "lat,lon". */
    static final int LOCATION = 9;
    /** No location: why. */
    static final int LOCATION_FAILED = 10;

    /** Push platforms, as the vault numbers them. */
    static final int UNIFIEDPUSH = 1;
    static final int FCM = 3;

    private static boolean loaded;

    // Whoever calls first (the activity, a service, a broadcast receiver in
    // a process of its own) gets the library: NativeActivity's own loading
    // happens outside Java and leaves these methods unresolved.
    static {
        load();
    }

    private Native() {}

    static synchronized void load() {
        if (!loaded) {
            System.loadLibrary("enclave_mobile");
            loaded = true;
        }
    }

    /** Start the vault on `profile` with no window, `service` serving it. */
    static native void start(Object service, String profile);

    /** In a helper process: run helper `name` on the socket `fd` (HelperService). */
    static native void helper(String name, String[] args, int fd);

    /** Hand the vault an event (see the constants). */
    static native void event(int kind, String data);
}
