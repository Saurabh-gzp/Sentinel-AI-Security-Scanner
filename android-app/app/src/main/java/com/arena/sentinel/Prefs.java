package com.arena.sentinel;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import android.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/** Preferences with Android Keystore-backed encryption for the user-supplied Gemini key. */
class Prefs {
    private static final String NAME = "sentinel";
    private static final String K_KEY = "gemini_key_ciphertext";
    private static final String K_MODEL = "gemini_model";
    private static final String K_VERIFIED = "key_verified";
    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String KEY_ALIAS = "sentinel_api_key_v1";

    static final String DEFAULT_KEY = "";
    static final String DEFAULT_MODEL = "models/gemini-3.5-flash-lite";

    static SharedPreferences sp(Context c) { return c.getSharedPreferences(NAME, Context.MODE_PRIVATE); }

    static String getKey(Context c) {
        String stored = sp(c).getString(K_KEY, "");
        if (stored.isEmpty()) return "";
        try {
            byte[] packed = Base64.decode(stored, Base64.DEFAULT);
            byte[] iv = new byte[12];
            byte[] ciphertext = new byte[packed.length - iv.length];
            System.arraycopy(packed, 0, iv, 0, iv.length);
            System.arraycopy(packed, iv.length, ciphertext, 0, ciphertext.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), new GCMParameterSpec(128, iv));
            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        } catch (Exception e) { return ""; }
    }

    static void setKey(Context c, String key) {
        String value = key == null ? "" : key.trim();
        SharedPreferences.Editor editor = sp(c).edit().putBoolean(K_VERIFIED, false);
        if (value.isEmpty()) { editor.remove(K_KEY).apply(); return; }
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey());
            byte[] ciphertext = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
            byte[] packed = new byte[cipher.getIV().length + ciphertext.length];
            System.arraycopy(cipher.getIV(), 0, packed, 0, cipher.getIV().length);
            System.arraycopy(ciphertext, 0, packed, cipher.getIV().length, ciphertext.length);
            editor.putString(K_KEY, Base64.encodeToString(packed, Base64.NO_WRAP)).apply();
        } catch (Exception e) { throw new IllegalStateException("Secure key storage unavailable", e); }
    }

    static boolean isKeyVerified(Context c) { return sp(c).getBoolean(K_VERIFIED, false); }
    static void setKeyVerified(Context c, boolean v) { sp(c).edit().putBoolean(K_VERIFIED, v).apply(); }
    static String getModel(Context c) { return sp(c).getString(K_MODEL, DEFAULT_MODEL); }
    static void setModel(Context c, String model) { sp(c).edit().putString(K_MODEL, model).apply(); }

    private static SecretKey getOrCreateKey() throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE);
        ks.load(null);
        if (ks.containsAlias(KEY_ALIAS)) return ((KeyStore.SecretKeyEntry) ks.getEntry(KEY_ALIAS, null)).getSecretKey();
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);
        generator.init(new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build());
        return generator.generateKey();
    }
}
