package com.aricummings.enclave;

import android.app.Service;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Binder;
import android.os.IBinder;
import android.os.Looper;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * The app's helpers in processes of their own (docs/15-client.md §1.2):
 * netd, with Tor and the mixnet client, in ":net", and mediad, which parses
 * pictures and clips, in the isolatedProcess ":media" (no network, no
 * files, no permissions). The vault asks for one through startHelper; this
 * binds the service and hands it one end of a socket pair over Binder, and
 * the helper speaks its usual protocol on it, as a program would on its
 * standard input and output. It ends when the vault closes its end.
 */
public class HelperService extends Service {
    private static final int RUN = 1;

    /** netd, in ":net". */
    public static class Net extends HelperService {}

    /** mediad, in the isolatedProcess ":media". */
    public static class Media extends HelperService {}

    private final Binder binder = new Binder() {
        @Override
        protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws android.os.RemoteException {
            if (code != RUN) {
                return super.onTransact(code, data, reply, flags);
            }
            String name = data.readString();
            String[] args = data.createStringArray();
            ParcelFileDescriptor fd = data.readFileDescriptor();
            if (name == null || args == null || fd == null) {
                return true;
            }
            Native.load();
            Native.helper(name, args, fd.detachFd());
            return true;
        }
    };

    @Override
    public IBinder onBind(Intent intent) {
        return binder;
    }

    /**
     * Start helper `name` with `args` in its process: the app's end of its
     * socket (a descriptor the caller then owns), or -1 to run it as a
     * thread instead. Called from the vault's thread, never the UI thread.
     */
    static int start(Context c, String name, String[] args) {
        Class<?> cls;
        if ("enclave-netd".equals(name)) {
            cls = Net.class;
        } else if ("enclave-mediad".equals(name)) {
            cls = Media.class;
        } else {
            return -1;
        }
        if (Looper.myLooper() == Looper.getMainLooper()) {
            return -1;
        }
        ParcelFileDescriptor[] pair;
        try {
            pair = ParcelFileDescriptor.createSocketPair();
        } catch (IOException e) {
            return -1;
        }
        CountDownLatch done = new CountDownLatch(1);
        boolean[] sent = {false};
        ServiceConnection conn = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName n, IBinder b) {
                Parcel p = Parcel.obtain();
                try {
                    p.writeString(name);
                    p.writeStringArray(args);
                    p.writeFileDescriptor(pair[1].getFileDescriptor());
                    sent[0] = b.transact(RUN, p, null, IBinder.FLAG_ONEWAY);
                } catch (android.os.RemoteException e) {
                    sent[0] = false;
                } finally {
                    p.recycle();
                    done.countDown();
                }
            }

            @Override
            public void onServiceDisconnected(ComponentName n) {}
        };
        // Bound from the application, so the helper lives as long as the
        // app's process (window or not), with its priority.
        Context app = c.getApplicationContext();
        boolean bound = app.bindService(new Intent(app, cls), conn, Context.BIND_AUTO_CREATE | Context.BIND_IMPORTANT);
        try {
            if (bound) {
                done.await(10, TimeUnit.SECONDS);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        try {
            pair[1].close();
        } catch (IOException e) {
            // Nothing to do.
        }
        if (!sent[0]) {
            try {
                pair[0].close();
            } catch (IOException e) {
                // Nothing to do.
            }
            return -1;
        }
        return pair[0].detachFd();
    }
}
