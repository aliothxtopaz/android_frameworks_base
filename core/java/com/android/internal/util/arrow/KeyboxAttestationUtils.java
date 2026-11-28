/*
 * SPDX-FileCopyrightText: 2025 Lunaris-AOSP
 * SPDX-FileCopyrightText: 2025 Project-PenguinOS
 * SPDX-License-Identifier: Apache-2.0
 *
 * Adapted from Lunaris-AOSP frameworks_base (16.2) / Project-PenguinOS.
 */
package com.android.internal.util.arrow;

import android.os.SystemProperties;
import android.util.Log;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.util.Locale;

/**
 * Verified-boot values used for the RootOfTrust attestation field.
 *
 * The real TEE value is preferred by the leaf hack; these helpers only provide
 * a deterministic fallback when the TEE does not expose one (or when the
 * software certificate-generation fallback is used).
 *
 * @hide
 */
public final class KeyboxAttestationUtils {
    private static final String TAG = "KeyboxAttestationUtils";

    private static final String PROP_VB_PUBLIC_KEY = "ro.boot.vbmeta.public_key_digest";
    private static final String PROP_VB_DIGEST = "ro.boot.vbmeta.digest";

    private KeyboxAttestationUtils() {}

    public static boolean isNullOrZero(byte[] value) {
        if (value == null || value.length == 0) return true;
        for (byte b : value) {
            if (b != 0) return false;
        }
        return true;
    }

    public static byte[] getBootKey() {
        byte[] fromProp = getPropDigest(PROP_VB_PUBLIC_KEY);
        if (fromProp != null) return fromProp;
        return getKeyboxDigest("bootkey");
    }

    public static byte[] getBootHash() {
        byte[] fromProp = getPropDigest(PROP_VB_DIGEST);
        if (fromProp != null) return fromProp;
        return getKeyboxDigest("boothash");
    }

    private static byte[] getPropDigest(String prop) {
        String value = SystemProperties.get(prop, "");
        if (value.length() != 64) return null;
        try {
            byte[] result = new byte[32];
            for (int i = 0; i < 32; i++) {
                int hi = Character.digit(value.charAt(i * 2), 16);
                int lo = Character.digit(value.charAt(i * 2 + 1), 16);
                if (hi < 0 || lo < 0) return null;
                result[i] = (byte) ((hi << 4) | lo);
            }
            return result;
        } catch (RuntimeException e) {
            Log.w(TAG, "Unable to parse " + prop, e);
            return null;
        }
    }

    /**
     * Deterministic fallback tied to the loaded keybox, so the attested value
     * does not change on every boot when the bootloader property is missing.
     */
    private static byte[] getKeyboxDigest(String domain) {
        try {
            KeyboxUtils.Keybox keybox = KeyboxUtils.getSigningKeybox("EC");
            if (keybox == null) keybox = KeyboxUtils.getSigningKeybox("RSA");
            if (keybox == null || keybox.certificates.isEmpty()) return new byte[32];

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            if (domain != null) {
                digest.update(domain.getBytes(StandardCharsets.UTF_8));
            }
            Certificate certificate = keybox.certificates.get(0);
            return digest.digest(certificate.getEncoded());
        } catch (Exception e) {
            Log.w(TAG, "Unable to derive " + domain + " from keybox", e);
            return new byte[32];
        }
    }

    static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format(Locale.ROOT, "%02x", b));
        }
        return sb.toString();
    }
}
