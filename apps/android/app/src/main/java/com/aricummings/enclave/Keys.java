package com.aricummings.enclave;

import android.content.Context;
import android.content.pm.PackageManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * The vault's keystore on Android (docs/14-storage.md §1.1): each secret is
 * sealed with AES-256-GCM under its own key in the Android Keystore
 * (StrongBox where the phone has one), which never leaves the secure
 * hardware; the sealed bytes live in the app's no-backup files. Names are
 * hex-encoded so any account string is a safe file name.
 */
final class Keys {
    private static final String STORE = "AndroidKeyStore";
    private static final int TAG_BITS = 128;

    private Keys() {}

    private static File dir(Context c) {
        File d = new File(c.getNoBackupFilesDir(), "keystore");
        d.mkdirs();
        return d;
    }

    private static String hex(String s) {
        StringBuilder b = new StringBuilder();
        for (byte x : s.getBytes(StandardCharsets.UTF_8)) {
            b.append(String.format("%02x", x));
        }
        return b.toString();
    }

    private static String unhex(String h) {
        byte[] out = new byte[h.length() / 2];
        for (int k = 0; k < out.length; k++) {
            out[k] = (byte) Integer.parseInt(h.substring(2 * k, 2 * k + 2), 16);
        }
        return new String(out, StandardCharsets.UTF_8);
    }

    private static String alias(String account) {
        return "enclave-" + hex(account);
    }

    private static SecretKey key(Context c, String account, boolean create) throws Exception {
        KeyStore ks = KeyStore.getInstance(STORE);
        ks.load(null);
        String alias = alias(account);
        if (ks.containsAlias(alias)) {
            return ((KeyStore.SecretKeyEntry) ks.getEntry(alias, null)).getSecretKey();
        }
        if (!create) {
            return null;
        }
        boolean strongBox = c.getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
        for (boolean sb : strongBox ? new boolean[] {true, false} : new boolean[] {false}) {
            try {
                KeyGenerator g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, STORE);
                g.init(new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setKeySize(256)
                        .setIsStrongBoxBacked(sb)
                        .build());
                return g.generateKey();
            } catch (Exception e) {
                // No StrongBox after all: the TEE keystore.
            }
        }
        return null;
    }

    static boolean available() {
        try {
            KeyStore.getInstance(STORE).load(null);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    static boolean set(Context c, String account, byte[] secret) {
        try {
            SecretKey k = key(c, account, true);
            if (k == null) {
                return false;
            }
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, k);
            cipher.updateAAD(account.getBytes(StandardCharsets.UTF_8));
            byte[] iv = cipher.getIV();
            byte[] sealed = cipher.doFinal(secret);
            File tmp = new File(dir(c), hex(account) + ".tmp");
            try (FileOutputStream out = new FileOutputStream(tmp)) {
                out.write(iv.length);
                out.write(iv);
                out.write(sealed);
                out.getFD().sync();
            }
            return tmp.renameTo(new File(dir(c), hex(account)));
        } catch (Exception e) {
            return false;
        }
    }

    static byte[] get(Context c, String account) {
        try {
            File f = new File(dir(c), hex(account));
            if (!f.exists()) {
                return null;
            }
            byte[] all = Files.readAllBytes(f.toPath());
            int n = all[0] & 0xff;
            SecretKey k = key(c, account, false);
            if (k == null) {
                return null;
            }
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, k, new GCMParameterSpec(TAG_BITS, Arrays.copyOfRange(all, 1, 1 + n)));
            cipher.updateAAD(account.getBytes(StandardCharsets.UTF_8));
            return cipher.doFinal(all, 1 + n, all.length - 1 - n);
        } catch (Exception e) {
            return null;
        }
    }

    static boolean delete(Context c, String account) {
        boolean ok = true;
        File f = new File(dir(c), hex(account));
        if (f.exists()) {
            ok = f.delete();
        }
        try {
            KeyStore ks = KeyStore.getInstance(STORE);
            ks.load(null);
            ks.deleteEntry(alias(account));
        } catch (Exception e) {
            // No key is fine.
        }
        return ok;
    }

    static String[] list(Context c, String prefix) {
        ArrayList<String> out = new ArrayList<>();
        File[] files = dir(c).listFiles();
        if (files != null) {
            for (File f : files) {
                String n = f.getName();
                if (n.endsWith(".tmp")) {
                    continue;
                }
                try {
                    String account = unhex(n);
                    if (account.startsWith(prefix)) {
                        out.add(account);
                    }
                } catch (Exception e) {
                    // Not ours.
                }
            }
        }
        return out.toArray(new String[0]);
    }
}
