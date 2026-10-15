package com.aricummings.enclave;

import android.app.Activity;
import android.app.BroadcastOptions;
import android.app.PendingIntent;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import java.util.List;
import java.util.UUID;

/**
 * UnifiedPush (the AND_3 protocol, unifiedpush.org/developers/spec/android):
 * the person's chosen distributor gives Enclave an endpoint, the vault
 * registers it with the home server (sealed to the push relay), and the
 * relay's wakes arrive here. A wake carries one fixed byte and nothing else.
 */
final class UnifiedPush {
    static final String REGISTER = "org.unifiedpush.android.distributor.REGISTER";
    static final String UNREGISTER = "org.unifiedpush.android.distributor.UNREGISTER";
    static final String MESSAGE_ACK = "org.unifiedpush.android.distributor.MESSAGE_ACK";
    static final String NEW_ENDPOINT = "org.unifiedpush.android.connector.NEW_ENDPOINT";
    static final String MESSAGE = "org.unifiedpush.android.connector.MESSAGE";
    static final String UNREGISTERED = "org.unifiedpush.android.connector.UNREGISTERED";
    static final String FAILED = "org.unifiedpush.android.connector.REGISTRATION_FAILED";
    static final String DISTRIBUTOR = "up-distributor";
    static final String INSTANCE = "up-instance";
    static final int LINK_REQUEST = 7;

    private UnifiedPush() {}

    /** Our registration's token (one per install, unguessable). */
    static String instance(Context c) {
        String t = EnclaveService.prefs(c).getString(INSTANCE, "");
        if (t.isEmpty()) {
            t = UUID.randomUUID().toString();
            EnclaveService.prefs(c).edit().putString(INSTANCE, t).apply();
        }
        return t;
    }

    /** Distributors installed on this phone. */
    static List<ResolveInfo> distributors(Context c) {
        return c.getPackageManager().queryBroadcastReceivers(new Intent(REGISTER), 0);
    }

    /** Ask the person to pick a distributor (its link screen), else take the only one. */
    static void link(Activity a) {
        Intent i = new Intent(Intent.ACTION_VIEW, Uri.parse("unifiedpush://link"));
        try {
            a.startActivityForResult(i, LINK_REQUEST);
        } catch (Exception e) {
            List<ResolveInfo> d = distributors(a);
            if (!d.isEmpty()) {
                use(a, d.get(0).activityInfo.packageName);
            }
        }
    }

    /** The link screen's answer: its PendingIntent names the distributor. */
    @SuppressWarnings("deprecation")
    static void linked(Activity a, int result, Intent data) {
        if (result != Activity.RESULT_OK || data == null) {
            return;
        }
        PendingIntent pi = Build.VERSION.SDK_INT >= 33
                ? data.getParcelableExtra("pi", PendingIntent.class)
                : (PendingIntent) data.getParcelableExtra("pi");
        if (pi != null) {
            use(a, pi.getCreatorPackage());
        }
    }

    static void use(Context c, String distributor) {
        EnclaveService.prefs(c).edit().putString(DISTRIBUTOR, distributor).putInt(EnclaveService.DELIVERY, Native.UNIFIEDPUSH).apply();
        send(c, REGISTER, distributor);
    }

    /** Stop using UnifiedPush (back to staying connected). */
    static void stop(Context c) {
        String d = EnclaveService.prefs(c).getString(DISTRIBUTOR, "");
        if (!d.isEmpty()) {
            send(c, UNREGISTER, d);
        }
        EnclaveService.prefs(c).edit().remove(DISTRIBUTOR).remove(EnclaveService.TOKEN).putInt(EnclaveService.DELIVERY, 0).apply();
        EnclaveService.deliver(c, Native.PUSH_TOKEN, Native.UNIFIEDPUSH + ":");
    }

    private static void send(Context c, String action, String distributor) {
        Intent i = new Intent(action).setPackage(distributor).putExtra("token", instance(c));
        if (REGISTER.equals(action)) {
            i.putExtra("message", "Enclave");
        }
        if (Build.VERSION.SDK_INT >= 34) {
            BroadcastOptions o = BroadcastOptions.makeBasic();
            o.setShareIdentityEnabled(true);
            c.sendBroadcast(i, null, o.toBundle());
        } else {
            Intent dummy = new Intent().setPackage("org.unifiedpush.dummy_app");
            i.putExtra("pi", PendingIntent.getBroadcast(c, 0, dummy, PendingIntent.FLAG_IMMUTABLE));
            c.sendBroadcast(i);
        }
    }

    /** The distributor's messages to us. */
    public static class Receiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context c, Intent i) {
            if (!instance(c).equals(i.getStringExtra("token"))) {
                return;
            }
            String d = EnclaveService.prefs(c).getString(DISTRIBUTOR, "");
            // Android 14 and later name the sender when it shares its
            // identity: only our distributor speaks for it.
            if (Build.VERSION.SDK_INT >= 34) {
                String from = getSentFromPackage();
                if (from != null && !from.equals(d)) {
                    return;
                }
            }
            String action = i.getAction();
            if (NEW_ENDPOINT.equals(action)) {
                String endpoint = i.getStringExtra("endpoint");
                if (endpoint != null) {
                    String token = Native.UNIFIEDPUSH + ":" + endpoint;
                    EnclaveService.prefs(c).edit().putString(EnclaveService.TOKEN, token).apply();
                    EnclaveService.deliver(c, Native.PUSH_TOKEN, token);
                }
            } else if (MESSAGE.equals(action)) {
                String id = i.getStringExtra("id");
                if (id != null && !d.isEmpty()) {
                    c.sendBroadcast(new Intent(MESSAGE_ACK).setPackage(d).putExtra("token", instance(c)).putExtra("id", id));
                }
                EnclaveService.deliver(c, Native.WAKE, "");
            } else if (UNREGISTERED.equals(action)) {
                // The distributor dropped us: back to staying connected.
                EnclaveService.prefs(c).edit().remove(EnclaveService.TOKEN).remove(DISTRIBUTOR).putInt(EnclaveService.DELIVERY, 0).apply();
                EnclaveService.deliver(c, Native.PUSH_TOKEN, Native.UNIFIEDPUSH + ":");
                if (EnclaveService.windowOpen) {
                    Native.event(Native.DELIVERY, "0");
                }
            }
            // REGISTRATION_FAILED and TEMP_UNAVAILABLE: the service stays
            // connected as before.
        }
    }

    /** The distributor raises us to the foreground while it delivers. */
    public static class Raise extends Service {
        @Override
        public IBinder onBind(Intent intent) {
            return new Binder();
        }
    }
}
