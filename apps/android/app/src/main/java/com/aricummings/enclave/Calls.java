package com.aricummings.enclave;

import android.annotation.SuppressLint;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Person;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.media.AudioAttributes;
import android.media.RingtoneManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.telecom.CallAudioState;
import android.telecom.Connection;
import android.telecom.ConnectionRequest;
import android.telecom.ConnectionService;
import android.telecom.DisconnectCause;
import android.telecom.PhoneAccount;
import android.telecom.PhoneAccountHandle;
import android.telecom.TelecomManager;
import android.telecom.VideoProfile;

/**
 * Calls on Android's own call handling (docs/11-calls.md §3.4): a
 * self-managed ConnectionService, so the system gives the call its audio
 * mode and focus, holds other calling apps for it, and a ringing call shows
 * full screen over the lock screen. Self-managed calls stay out of the
 * system's call log. The vault reports the call's state (report); what the
 * person does on the call screen or the notification comes back as
 * Native.CALL events: "answer", "end", "mute:1", "mute:0".
 */
final class Calls {
    static final int INCOMING = 1;
    static final int OUTGOING = 2;
    static final int CONNECTED = 3;
    static final int ENDED = 4;

    private static final String CHANNEL = "calls";
    private static final int NOTIFICATION = 3;
    private static final String DECLINE = "com.aricummings.enclave.DECLINE";
    /** The extra on the activity intent: "ring" (full screen) or "answer". */
    static final String EXTRA = "call";

    private static Context app;
    private static Line current;
    private static int state = ENDED;
    private static String name = "Enclave";
    private static boolean video;
    private static boolean registered;

    private Calls() {}

    private static PhoneAccountHandle account(Context c) {
        return new PhoneAccountHandle(new ComponentName(c, Service.class), "enclave");
    }

    /** No number: the system shows the name we give it. */
    private static Uri address() {
        return Uri.fromParts("enclave", "call", null);
    }

    private static TelecomManager telecom(Context c) {
        TelecomManager tm = c.getSystemService(TelecomManager.class);
        if (!registered) {
            tm.registerPhoneAccount(PhoneAccount.builder(account(c), "Enclave")
                    .setCapabilities(PhoneAccount.CAPABILITY_SELF_MANAGED
                            | PhoneAccount.CAPABILITY_VIDEO_CALLING
                            | PhoneAccount.CAPABILITY_SUPPORTS_VIDEO_CALLING)
                    .addSupportedUriScheme("enclave")
                    .build());
            registered = true;
        }
        return tm;
    }

    /** The vault's report of the call (one of the states above). */
    @SuppressLint("MissingPermission") // MANAGE_OWN_CALLS, granted at install
    static synchronized void report(Context c, int now, String who, boolean withVideo) {
        app = c.getApplicationContext();
        int was = state;
        state = now;
        switch (now) {
            case INCOMING:
                name = who;
                video = withVideo;
                if (was == INCOMING) {
                    if (current != null) {
                        current.setCallerDisplayName(who, TelecomManager.PRESENTATION_ALLOWED);
                    }
                    ring();
                    return;
                }
                Bundle in = new Bundle();
                in.putParcelable(TelecomManager.EXTRA_INCOMING_CALL_ADDRESS, address());
                try {
                    telecom(app).addNewIncomingCall(account(app), in);
                } catch (RuntimeException e) {
                    // No telecom service (some tablets): the notification alone.
                    ring();
                }
                break;
            case OUTGOING:
                name = who;
                video = withVideo;
                EnclaveService.call(app, true);
                Bundle out = new Bundle();
                out.putParcelable(TelecomManager.EXTRA_PHONE_ACCOUNT_HANDLE, account(app));
                out.putInt(TelecomManager.EXTRA_START_CALL_WITH_VIDEO_STATE, videoState());
                try {
                    telecom(app).placeCall(address(), out);
                } catch (RuntimeException e) {
                    // The call goes on without the system knowing of it.
                }
                break;
            case CONNECTED:
                quiet();
                if (was != CONNECTED) {
                    EnclaveService.call(app, true);
                }
                if (current != null) {
                    current.setActive();
                }
                break;
            default:
                quiet();
                if (was != ENDED) {
                    EnclaveService.call(app, false);
                }
                if (current != null) {
                    current.finish(new DisconnectCause(DisconnectCause.REMOTE));
                }
                break;
        }
    }

    /** The person answered (the notification's Answer, through the activity). */
    static synchronized void answer() {
        if (current != null) {
            current.onAnswer(videoState());
        } else if (state == INCOMING) {
            quiet();
            EnclaveService.call(app, true);
            Native.event(Native.CALL, "answer");
        }
    }

    private static int videoState() {
        return video ? VideoProfile.STATE_BIDIRECTIONAL : VideoProfile.STATE_AUDIO_ONLY;
    }

    /** The ringing notification: full screen when the phone is locked or idle. */
    private static void ring() {
        NotificationManager nm = app.getSystemService(NotificationManager.class);
        if (nm.getNotificationChannel(CHANNEL) == null) {
            NotificationChannel ch = new NotificationChannel(CHANNEL, "Calls", NotificationManager.IMPORTANCE_HIGH);
            ch.setSound(RingtoneManager.getDefaultUri(RingtoneManager.TYPE_RINGTONE),
                    new AudioAttributes.Builder()
                            .setUsage(AudioAttributes.USAGE_NOTIFICATION_RINGTONE)
                            .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                            .build());
            ch.enableVibration(true);
            nm.createNotificationChannel(ch);
        }
        int flags = PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT;
        Intent show = new Intent(app, EnclaveActivity.class)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP)
                .putExtra(EXTRA, "ring");
        Intent take = new Intent(app, EnclaveActivity.class)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP)
                .putExtra(EXTRA, "answer");
        PendingIntent full = PendingIntent.getActivity(app, 1, show, flags);
        PendingIntent yes = PendingIntent.getActivity(app, 2, take, flags);
        PendingIntent no = PendingIntent.getBroadcast(app, 3,
                new Intent(app, Decline.class).setAction(DECLINE), flags);
        String kind = video ? "Video call" : "Voice call";
        Notification.Builder b = new Notification.Builder(app, CHANNEL)
                .setSmallIcon(app.getApplicationInfo().icon)
                .setContentTitle(name)
                .setContentText(kind)
                .setCategory(Notification.CATEGORY_CALL)
                .setOngoing(true)
                .setFullScreenIntent(full, true)
                .setContentIntent(full)
                .setVisibility(Notification.VISIBILITY_PRIVATE)
                // On the lock screen: that a call rings, not who calls.
                .setPublicVersion(new Notification.Builder(app, CHANNEL)
                        .setSmallIcon(app.getApplicationInfo().icon)
                        .setContentTitle("Enclave")
                        .setContentText(kind)
                        .build());
        if (Build.VERSION.SDK_INT >= 31) {
            b.setStyle(Notification.CallStyle.forIncomingCall(
                    new Person.Builder().setName(name).build(), no, yes));
        } else {
            b.addAction(new Notification.Action.Builder(null, "Decline", no).build());
            b.addAction(new Notification.Action.Builder(null, "Answer", yes).build());
        }
        Notification n = b.build();
        n.flags |= Notification.FLAG_INSISTENT;
        nm.notify(NOTIFICATION, n);
    }

    private static void quiet() {
        if (app != null) {
            app.getSystemService(NotificationManager.class).cancel(NOTIFICATION);
        }
    }

    /** The notification's Decline. */
    public static final class Decline extends BroadcastReceiver {
        @Override
        public void onReceive(Context c, Intent i) {
            synchronized (Calls.class) {
                if (current != null) {
                    current.onReject();
                } else {
                    quiet();
                    Native.event(Native.CALL, "end");
                }
            }
        }
    }

    /** One call, as the system sees it. */
    static final class Line extends Connection {
        private boolean muted;

        Line() {
            setConnectionProperties(PROPERTY_SELF_MANAGED);
            setConnectionCapabilities(CAPABILITY_MUTE);
            setAudioModeIsVoip(true);
            setAddress(address(), TelecomManager.PRESENTATION_ALLOWED);
            setCallerDisplayName(name, TelecomManager.PRESENTATION_ALLOWED);
            setVideoState(videoState());
        }

        @Override
        public void onShowIncomingCallUi() {
            synchronized (Calls.class) {
                ring();
            }
        }

        @Override
        public void onAnswer() {
            onAnswer(videoState());
        }

        @Override
        public void onAnswer(int videoState) {
            synchronized (Calls.class) {
                quiet();
                setActive();
                EnclaveService.call(app, true);
                Native.event(Native.CALL, "answer");
            }
        }

        @Override
        public void onReject() {
            hangUp(DisconnectCause.REJECTED);
        }

        @Override
        public void onDisconnect() {
            hangUp(DisconnectCause.LOCAL);
        }

        @Override
        public void onAbort() {
            hangUp(DisconnectCause.LOCAL);
        }

        @Override
        @SuppressWarnings("deprecation") // onMuteStateChanged from Android 14
        public void onCallAudioStateChanged(CallAudioState s) {
            onMuteStateChanged(s.isMuted());
        }

        @Override
        public void onMuteStateChanged(boolean on) {
            if (on != muted) {
                muted = on;
                Native.event(Native.CALL, muted ? "mute:1" : "mute:0");
            }
        }

        private void hangUp(int cause) {
            synchronized (Calls.class) {
                quiet();
                finish(new DisconnectCause(cause));
                Native.event(Native.CALL, "end");
            }
        }

        void finish(DisconnectCause cause) {
            setDisconnected(cause);
            destroy();
            if (current == this) {
                current = null;
            }
        }
    }

    /** The ConnectionService the system binds while a call is on. */
    public static final class Service extends ConnectionService {
        @Override
        public Connection onCreateIncomingConnection(PhoneAccountHandle account, ConnectionRequest request) {
            return open(false);
        }

        @Override
        public Connection onCreateOutgoingConnection(PhoneAccountHandle account, ConnectionRequest request) {
            return open(true);
        }

        @Override
        public void onCreateIncomingConnectionFailed(PhoneAccountHandle account, ConnectionRequest request) {
            // Another call holds the phone: the app's own screen still rings.
            synchronized (Calls.class) {
                if (state == INCOMING) {
                    ring();
                }
            }
        }

        private static Connection open(boolean outgoing) {
            synchronized (Calls.class) {
                // The call may have ended (or connected) before the system
                // got here.
                if (state == ENDED) {
                    return Connection.createFailedConnection(new DisconnectCause(DisconnectCause.CANCELED));
                }
                Line l = new Line();
                current = l;
                if (state == CONNECTED) {
                    l.setActive();
                } else if (outgoing) {
                    l.setDialing();
                } else {
                    l.setRinging();
                }
                return l;
            }
        }
    }
}
