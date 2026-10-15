package com.aricummings.enclave;

import android.content.Context;

/** The F-Droid build has no Google push (UnifiedPush or staying connected). */
final class Fcm {
    private Fcm() {}

    static boolean available() {
        return false;
    }

    static void start(Context c) {}

    static void stop(Context c) {}
}
