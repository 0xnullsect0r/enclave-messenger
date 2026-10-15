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

    /** Push platforms, as the vault numbers them. */
    static final int UNIFIEDPUSH = 1;
    static final int FCM = 3;

    private static boolean loaded;

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
