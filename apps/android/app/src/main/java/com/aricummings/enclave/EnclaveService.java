package com.aricummings.enclave;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import java.io.File;
import java.util.ArrayDeque;

/**
 * Keeps the vault running with no window (docs/10-push.md §5): as the
 * default, a foreground service that stays connected (the Background
 * traffic profile); with a push service chosen instead (UnifiedPush, or
 * Firebase in the Play build), started by a wake and stopped again a minute
 * after the last one while no window is open.
 */
public class EnclaveService extends Service {
    static final String PREFS = "enclave";
    /** 0 stay connected, 1 UnifiedPush, 3 Firebase. */
    static final String DELIVERY = "delivery";
    static final String TOKEN = "push-token";
    private static final String CHANNEL = "connection";
    private static final long LINGER_MS = 60_000;
    /** The service's own notification; messages use 1, as the activity's. */
    private static final int FOREGROUND_ID = 7;

    private static final ArrayDeque<int[]> KINDS = new ArrayDeque<>();
    private static final ArrayDeque<String> DATA = new ArrayDeque<>();
    private static boolean started;
    static volatile boolean windowOpen;

    private final Handler main = new Handler(Looper.getMainLooper());

    static SharedPreferences prefs(Context c) {
        return c.getSharedPreferences(PREFS, MODE_PRIVATE);
    }

    static int delivery(Context c) {
        return prefs(c).getInt(DELIVERY, 0);
    }

    /** Pass an event to the vault, starting it first if needed. */
    static void deliver(Context c, int kind, String data) {
        synchronized (KINDS) {
            KINDS.add(new int[] {kind});
            DATA.add(data);
        }
        start(c);
    }

    /** Start (or poke) the service. */
    static void start(Context c) {
        Intent i = new Intent(c, EnclaveService.class);
        try {
            c.startForegroundService(i);
        } catch (Exception e) {
            // Not allowed from the background right now; the next window
            // or wake starts it.
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm.getNotificationChannel(CHANNEL) == null) {
            nm.createNotificationChannel(new NotificationChannel(CHANNEL, "Connection", NotificationManager.IMPORTANCE_MIN));
        }
        Intent open = new Intent(this, EnclaveActivity.class);
        Notification n = new Notification.Builder(this, CHANNEL)
                .setSmallIcon(getApplicationInfo().icon)
                .setContentTitle("Enclave")
                .setContentText(delivery(this) == 0 ? "Connected, so messages arrive" : "Fetching new messages")
                .setContentIntent(PendingIntent.getActivity(this, 0, open, PendingIntent.FLAG_IMMUTABLE))
                .setOngoing(true)
                .build();
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(FOREGROUND_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(FOREGROUND_ID, n);
        }
        Native.load();
        synchronized (KINDS) {
            if (!started) {
                started = true;
                Native.start(this, new File(getFilesDir(), "profile").getAbsolutePath());
                // The push token we hold, registered afresh each start.
                String token = prefs(this).getString(TOKEN, "");
                if (!token.isEmpty()) {
                    KINDS.add(new int[] {Native.PUSH_TOKEN});
                    DATA.add(token);
                }
            }
            while (!KINDS.isEmpty()) {
                Native.event(KINDS.poll()[0], DATA.poll());
            }
        }
        lingerOrStay();
        return START_STICKY;
    }

    /** With a push service chosen and no window, stop a minute after the last wake. */
    private void lingerOrStay() {
        main.removeCallbacksAndMessages(null);
        if (delivery(this) != 0) {
            main.postDelayed(() -> {
                if (!windowOpen) {
                    stopForeground(STOP_FOREGROUND_REMOVE);
                    stopSelf();
                }
            }, LINGER_MS);
        }
    }

    /** After a restart, stay connected again (with no push service chosen). */
    public static class Boot extends android.content.BroadcastReceiver {
        @Override
        public void onReceive(Context c, Intent i) {
            if (Intent.ACTION_BOOT_COMPLETED.equals(i.getAction())
                    || Intent.ACTION_MY_PACKAGE_REPLACED.equals(i.getAction())) {
                if (delivery(c) == 0) {
                    start(c);
                } else if (delivery(c) == Native.FCM) {
                    Fcm.start(c);
                }
            }
        }
    }

    // What the vault calls on this service while no window is open.

    /** Show a notification. */
    public void notify(String title, String body) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm.getNotificationChannel("messages") == null) {
            nm.createNotificationChannel(new NotificationChannel("messages", "Messages", NotificationManager.IMPORTANCE_HIGH));
        }
        Intent open = new Intent(this, EnclaveActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        nm.notify(1, new Notification.Builder(this, "messages")
                .setSmallIcon(getApplicationInfo().icon)
                .setContentTitle(title)
                .setContentText(body)
                .setContentIntent(PendingIntent.getActivity(this, 0, open, PendingIntent.FLAG_IMMUTABLE))
                .setAutoCancel(true)
                .setVisibility(Notification.VISIBILITY_PRIVATE)
                .build());
    }

    public boolean keySet(String account, byte[] secret) {
        return Keys.set(this, account, secret);
    }

    public byte[] keyGet(String account) {
        return Keys.get(this, account);
    }

    public boolean keyDelete(String account) {
        return Keys.delete(this, account);
    }

    public String[] keyList(String prefix) {
        return Keys.list(this, prefix);
    }

    public boolean keyAvailable() {
        return Keys.available();
    }
}
