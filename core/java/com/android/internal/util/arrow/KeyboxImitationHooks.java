/*
 * SPDX-FileCopyrightText: 2024 Paranoid Android
 * SPDX-FileCopyrightText: 2025 Neoteric OS
 * SPDX-FileCopyrightText: 2025 Lunaris-AOSP
 * SPDX-FileCopyrightText: 2025 Project-PenguinOS
 * SPDX-License-Identifier: Apache-2.0
 *
 * Real-key leaf hacking adapted from Lunaris-AOSP frameworks_base (16.2) /
 * Project-PenguinOS CertificateHacker. The software certificate-generation
 * path is kept only as a fallback for keys that cannot be created in the TEE.
 */
package com.android.internal.util.arrow;

import android.hardware.security.keymint.Algorithm;
import android.hardware.security.keymint.KeyOrigin;
import android.hardware.security.keymint.KeyParameter;
import android.hardware.security.keymint.KeyParameterValue;
import android.hardware.security.keymint.KeyPurpose;
import android.hardware.security.keymint.Tag;
import android.os.Process;
import android.system.keystore2.Authorization;
import android.system.keystore2.IKeystoreSecurityLevel;
import android.system.keystore2.KeyDescriptor;
import android.system.keystore2.KeyEntryResponse;
import android.system.keystore2.KeyMetadata;
import android.util.Log;

import com.android.internal.util.arrow.KeyboxChainGenerator.KeyGenParameters;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * @hide
 */
public class KeyboxImitationHooks {

    private static final String TAG = "KeyboxImitationHooks";
    private static final boolean DEBUG = Log.isLoggable(TAG, Log.DEBUG);

    // Prevents re-entering the hack when updateSubcomponents()/getKeyEntry() are
    // called from inside the hack itself.
    private static final ThreadLocal<Boolean> sInHack = ThreadLocal.withInitial(() -> false);

    /**
     * Cached cert-generation fallback. Only populated when a real key could not
     * be created at all, so a fake key entry can never replace a usable TEE key.
     */
    public static KeyEntryResponse getFallbackKeyEntry(KeyDescriptor descriptor) {
        KeyEntryResponse spoofed = KeyboxUtils.retrieve(Process.myUid(), descriptor.alias);
        if (spoofed == null) {
            return null;
        }
        if (!KeyProviderManager.isKeyboxAvailable()) {
            KeyboxUtils.remove(Process.myUid(), descriptor.alias);
            return null;
        }
        Log.i(TAG, "Using cert-generation fallback for " + descriptor.alias
                + " uid=" + Process.myUid());
        return spoofed;
    }

    /**
     * Rewrites the leaf of a chain returned for an existing keystore key. The
     * private key stays in the TEE; only the certificate metadata changes.
     */
    public static KeyEntryResponse onGetKeyEntry(KeyDescriptor descriptor,
            KeyEntryResponse response) {
        if (response == null || response.metadata == null
                || !KeyProviderManager.isKeyboxAvailable()
                || sInHack.get()) {
            return response;
        }

        int uid = Process.myUid();
        if (response.metadata.certificate == null) {
            return response;
        }
        if (KeyboxUtils.isKeyboxSigned(uid, descriptor.alias)) {
            dlog("chain for " + descriptor.alias + " already keybox-signed (cached)");
            return response;
        }

        sInHack.set(true);
        try {
            Certificate[] chain = KeyboxUtils.getCertificateChain(response.metadata);
            if (chain.length == 0) return response;
            if (KeyboxCertificateHacker.isKeyboxSigned(chain)) {
                KeyboxUtils.markKeyboxSigned(uid, descriptor.alias);
                dlog("chain for " + descriptor.alias + " already keybox-signed");
                return response;
            }

            Certificate[] hacked = KeyboxCertificateHacker.hackCertificateChain(
                    descriptor.alias, chain);
            if (hacked == chain) {
                dlog("chain for " + descriptor.alias + " already handled");
                return response;
            }

            KeyboxUtils.putCertificateChain(response.metadata, hacked);
            boolean persisted = KeyboxUtils.persistCertificateChain(
                    metadataKey(descriptor, response.metadata), hacked);
            if (persisted) {
                KeyboxUtils.markKeyboxSigned(uid, descriptor.alias);
            }
            Log.i(TAG, "leaf-hacked chain for " + descriptor.alias
                    + " uid=" + uid
                    + " certs=" + hacked.length
                    + " persisted=" + persisted
                    + " os=" + KeyboxChainGenerator.getOsVersion()
                    + " patch=" + KeyboxChainGenerator.getPatchLevel()
                    + " " + leafInfo(hacked));
            return response;
        } catch (Exception e) {
            Log.e(TAG, "Failed to leaf-hack key entry for " + descriptor.alias, e);
            return response;
        } finally {
            sInHack.set(false);
        }
    }

    /**
     * Applies the leaf hack to the metadata returned by the real generateKey()
     * call, so callers that use the certificate straight from the KeyPair get
     * the keybox chain too.
     */
    public static KeyMetadata onGenerateKey(KeyDescriptor descriptor, KeyMetadata metadata,
            KeyParameter[] args) {
        if (metadata == null || metadata.certificate == null
                || !KeyProviderManager.isKeyboxAvailable()
                || sInHack.get()) {
            return metadata;
        }
        if (!hasAttestationChallenge(args)) {
            dlog("no attestation challenge for " + descriptor.alias + ", leaving chain untouched");
            return metadata;
        }

        int uid = Process.myUid();
        sInHack.set(true);
        try {
            Certificate[] chain = KeyboxUtils.getCertificateChain(metadata);
            if (chain.length == 0) return metadata;

            Certificate[] hacked = KeyboxCertificateHacker.hackCertificateChain(
                    descriptor.alias, chain);
            if (hacked == chain) {
                Log.i(TAG, "generateKey for " + descriptor.alias + " uid=" + uid
                        + ": chain unchanged");
                return metadata;
            }

            KeyboxUtils.putCertificateChain(metadata, hacked);
            boolean persisted = KeyboxUtils.persistCertificateChain(
                    metadataKey(descriptor, metadata), hacked);
            if (persisted) {
                KeyboxUtils.markKeyboxSigned(uid, descriptor.alias);
            }
            Log.i(TAG, "leaf-hacked chain for " + descriptor.alias
                    + " uid=" + uid
                    + " source=generateKey"
                    + " certs=" + hacked.length
                    + " persisted=" + persisted
                    + " os=" + KeyboxChainGenerator.getOsVersion()
                    + " patch=" + KeyboxChainGenerator.getPatchLevel()
                    + " " + leafInfo(hacked));
            return metadata;
        } catch (Exception e) {
            Log.e(TAG, "Failed to leaf-hack generated key for " + descriptor.alias, e);
            return metadata;
        } finally {
            sInHack.set(false);
        }
    }

    /**
     * Software key + keybox-signed leaf fallback. This key cannot perform TEE
     * signing, so it is only used when the real generateKey() threw.
     */
    public static KeyMetadata generateFallbackKey(IKeystoreSecurityLevel level,
            KeyDescriptor descriptor, Collection<KeyParameter> args) {
        if (!KeyProviderManager.isKeyboxAvailable()) {
            return null;
        }

        KeyGenParameters params = new KeyGenParameters(
                args.toArray(new KeyParameter[args.size()]));

        if (params.attestationChallenge == null) {
            return null;
        }

        if (params.purpose == null || !params.purpose.contains(KeyPurpose.SIGN)) {
            return null;
        }

        if (!params.noAuthRequired) {
            return null;
        }

        if (params.algorithm != Algorithm.EC && params.algorithm != Algorithm.RSA) {
            Log.w(TAG, "Unsupported algorithm: " + params.algorithm);
            return null;
        }

        int uid = Process.myUid();
        try {
            List<Certificate> chain = KeyboxChainGenerator.generateCertChain(
                    uid, descriptor, params);
            if (chain == null || chain.isEmpty()) {
                return null;
            }
            KeyEntryResponse response = buildResponse(level, chain, params, descriptor);
            if (response == null) {
                return null;
            }
            KeyboxUtils.append(uid, descriptor.alias, response);
            Log.w(TAG, "cert-generation fallback for " + descriptor.alias + " uid=" + uid
                    + " os=" + params.osVersion + " patch=" + params.osPatchLevel
                    + " (real key unavailable; signing will not work)");
            return response.metadata;
        } catch (Exception e) {
            Log.e(TAG, "Failed to generate fallback key", e);
            return null;
        }
    }

    /**
     * Some Keymaster HALs cannot attest the device-ID tags (-66 CANNOT_ATTEST_IDS).
     * Strip them from the real generateKey() request; the keybox leaf hack adds the
     * spoofed IDs afterwards. Only applies to processes we are actually spoofing.
     */
    public static KeyParameter[] withoutAttestationIds(KeyParameter[] args) {
        if (args == null || args.length == 0
                || !KeyProviderManager.isKeyboxAvailable()
                || !KeyboxUtils.shouldSpoofAttestationIds()) {
            return args;
        }
        List<KeyParameter> filtered = new ArrayList<>(args.length);
        boolean stripped = false;
        for (KeyParameter parameter : args) {
            if (isAttestationIdTag(parameter.tag)) {
                stripped = true;
            } else {
                filtered.add(parameter);
            }
        }
        if (!stripped) return args;
        Log.i(TAG, "Dropped device-ID attestation parameters the HAL cannot attest;"
                + " the keybox leaf will carry the spoofed IDs");
        return filtered.toArray(new KeyParameter[0]);
    }

    private static boolean isAttestationIdTag(int tag) {
        switch (tag) {
            case Tag.ATTESTATION_ID_BRAND:
            case Tag.ATTESTATION_ID_DEVICE:
            case Tag.ATTESTATION_ID_PRODUCT:
            case Tag.ATTESTATION_ID_SERIAL:
            case Tag.ATTESTATION_ID_IMEI:
            case Tag.ATTESTATION_ID_MEID:
            case Tag.ATTESTATION_ID_MANUFACTURER:
            case Tag.ATTESTATION_ID_MODEL:
                return true;
            default:
                return false;
        }
    }

    private static boolean hasAttestationChallenge(KeyParameter[] args) {
        if (args == null) return false;
        for (KeyParameter parameter : args) {
            if (parameter.tag == Tag.ATTESTATION_CHALLENGE) {
                return true;
            }
        }
        return false;
    }

    private static KeyDescriptor metadataKey(KeyDescriptor fallback, KeyMetadata metadata) {
        return metadata.key != null ? metadata.key : fallback;
    }

    private static String leafInfo(Certificate[] chain) {
        if (chain.length == 0 || !(chain[0] instanceof X509Certificate)) return "";
        X509Certificate leaf = (X509Certificate) chain[0];
        return "leafIssuer=" + leaf.getIssuerX500Principal().getName();
    }

    private static KeyEntryResponse buildResponse(
            IKeystoreSecurityLevel level,
            List<Certificate> chain,
            KeyGenParameters params,
            KeyDescriptor descriptor
    ) {
        try {
            KeyEntryResponse response = new KeyEntryResponse();
            KeyMetadata metadata = new KeyMetadata();
            metadata.keySecurityLevel = params.securityLevel;

            KeyboxUtils.putCertificateChain(metadata, chain.toArray(new Certificate[chain.size()]));

            KeyDescriptor d = new KeyDescriptor();
            d.domain = descriptor.domain;
            d.nspace = descriptor.nspace;
            d.alias = descriptor.alias;
            metadata.key = d;

            List<Authorization> authorizations = new ArrayList<>();
            Authorization a;

            for (Integer i : params.purpose) {
                a = new Authorization();
                a.keyParameter = new KeyParameter();
                a.keyParameter.tag = Tag.PURPOSE;
                a.keyParameter.value = KeyParameterValue.keyPurpose(i);
                a.securityLevel = params.securityLevel;
                authorizations.add(a);
            }

            for (Integer i : params.digest) {
                a = new Authorization();
                a.keyParameter = new KeyParameter();
                a.keyParameter.tag = Tag.DIGEST;
                a.keyParameter.value = KeyParameterValue.digest(i);
                a.securityLevel = params.securityLevel;
                authorizations.add(a);
            }

            a = new Authorization();
            a.keyParameter = new KeyParameter();
            a.keyParameter.tag = Tag.ALGORITHM;
            a.keyParameter.value = KeyParameterValue.algorithm(params.algorithm);
            a.securityLevel = params.securityLevel;
            authorizations.add(a);

            a = new Authorization();
            a.keyParameter = new KeyParameter();
            a.keyParameter.tag = Tag.KEY_SIZE;
            a.keyParameter.value = KeyParameterValue.integer(params.keySize);
            a.securityLevel = params.securityLevel;
            authorizations.add(a);

            a = new Authorization();
            a.keyParameter = new KeyParameter();
            a.keyParameter.tag = Tag.EC_CURVE;
            a.keyParameter.value = KeyParameterValue.ecCurve(params.ecCurve);
            a.securityLevel = params.securityLevel;
            authorizations.add(a);

            a = new Authorization();
            a.keyParameter = new KeyParameter();
            a.keyParameter.tag = Tag.NO_AUTH_REQUIRED;
            a.keyParameter.value = KeyParameterValue.boolValue(true);
            a.securityLevel = params.securityLevel;
            authorizations.add(a);

            a = new Authorization();
            a.keyParameter = new KeyParameter();
            a.keyParameter.tag = Tag.ORIGIN;
            a.keyParameter.value = KeyParameterValue.origin(params.origin);
            a.securityLevel = params.securityLevel;
            authorizations.add(a);

            a = new Authorization();
            a.keyParameter = new KeyParameter();
            a.keyParameter.tag = Tag.OS_VERSION;
            a.keyParameter.value = KeyParameterValue.integer(params.osVersion);
            a.securityLevel = params.securityLevel;
            authorizations.add(a);

            a = new Authorization();
            a.keyParameter = new KeyParameter();
            a.keyParameter.tag = Tag.OS_PATCHLEVEL;
            a.keyParameter.value = KeyParameterValue.integer(params.osPatchLevel);
            a.securityLevel = params.securityLevel;
            authorizations.add(a);

            a = new Authorization();
            a.keyParameter = new KeyParameter();
            a.keyParameter.tag = Tag.VENDOR_PATCHLEVEL;
            a.keyParameter.value = KeyParameterValue.integer(params.vendorPatchLevel);
            a.securityLevel = params.securityLevel;
            authorizations.add(a);

            a = new Authorization();
            a.keyParameter = new KeyParameter();
            a.keyParameter.tag = Tag.BOOT_PATCHLEVEL;
            a.keyParameter.value = KeyParameterValue.integer(params.bootPatchLevel);
            a.securityLevel = params.securityLevel;
            authorizations.add(a);

            a = new Authorization();
            a.keyParameter = new KeyParameter();
            a.keyParameter.tag = Tag.CREATION_DATETIME;
            a.keyParameter.value = KeyParameterValue.longInteger(params.creationDateTime);
            a.securityLevel = params.securityLevel;
            authorizations.add(a);

            a = new Authorization();
            a.keyParameter = new KeyParameter();
            a.keyParameter.tag = Tag.USER_ID;
            a.keyParameter.value = KeyParameterValue.integer(params.userId);
            a.securityLevel = params.securityLevel;
            authorizations.add(a);

            metadata.authorizations = authorizations.toArray(new Authorization[0]);
            metadata.modificationTimeMs = System.currentTimeMillis();
            response.metadata = metadata;
            response.iSecurityLevel = level;
            return response;
        } catch (Exception e) {
            Log.e(TAG, "Failed to build key entry response", e);
            return null;
        }
    }

    private static void dlog(String msg) {
        if (DEBUG) Log.d(TAG, msg);
    }
}
