package com.aricummings.enclave;

import android.content.Context;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.firebase.messaging.FirebaseMessaging;
import com.google.firebase.messaging.FirebaseMessagingService;
import com.google.firebase.messaging.RemoteMessage;

/**
 * Google's push service (the Play build, docs/10-push.md §5). Firebase is
 * set up by hand from the build's project settings (no google-services
 * file, nothing collected: auto-init and analytics are off in the
 * manifest), only once the person chooses it. A wake is an empty
 * high-priority message; the token goes to the vault, which registers it
 * sealed to the push relay.
 */
final class Fcm {
    private Fcm() {}

    static boolean available() {
        return !BuildConfig.FCM_APP_ID.isEmpty();
    }

    private static FirebaseApp app(Context c) {
        if (!FirebaseApp.getApps(c).isEmpty()) {
            return FirebaseApp.getInstance();
        }
        FirebaseOptions o = new FirebaseOptions.Builder()
                .setProjectId(BuildConfig.FCM_PROJECT_ID)
                .setApplicationId(BuildConfig.FCM_APP_ID)
                .setApiKey(BuildConfig.FCM_API_KEY)
                .setGcmSenderId(BuildConfig.FCM_SENDER_ID)
                .build();
        return FirebaseApp.initializeApp(c.getApplicationContext(), o);
    }

    /** Get (or refresh) the token and hand it to the vault. */
    static void start(Context c) {
        if (!available()) {
            return;
        }
        app(c);
        FirebaseMessaging m = FirebaseMessaging.getInstance();
        m.setAutoInitEnabled(true);
        m.getToken().addOnSuccessListener(t -> Service.token(c, t));
    }

    /** Stop: the token is deleted and the vault forgets it. */
    static void stop(Context c) {
        if (!available()) {
            return;
        }
        app(c);
        FirebaseMessaging m = FirebaseMessaging.getInstance();
        m.setAutoInitEnabled(false);
        m.deleteToken();
        EnclaveService.prefs(c).edit().remove(EnclaveService.TOKEN).apply();
        EnclaveService.deliver(c, Native.PUSH_TOKEN, Native.FCM + ":");
    }

    /** Firebase's messages: new tokens and wakes. */
    public static class Service extends FirebaseMessagingService {
        static void token(Context c, String t) {
            if (EnclaveService.delivery(c) != Native.FCM) {
                return;
            }
            String token = Native.FCM + ":" + t;
            EnclaveService.prefs(c).edit().putString(EnclaveService.TOKEN, token).apply();
            EnclaveService.deliver(c, Native.PUSH_TOKEN, token);
        }

        @Override
        public void onNewToken(String t) {
            token(this, t);
        }

        @Override
        public void onMessageReceived(RemoteMessage m) {
            // High priority, so starting the service from here is allowed.
            if (EnclaveService.delivery(this) == Native.FCM) {
                EnclaveService.deliver(this, Native.WAKE, "");
            }
        }
    }
}
