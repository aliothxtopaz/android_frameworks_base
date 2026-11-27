/*
 * SPDX-FileCopyrightText: 2025 Neoteric OS
 * SPDX-FileCopyrightText: 2025 The halogenOS Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.internal.util.arrow;

import android.app.ActivityThread;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.res.Resources;
import android.hardware.security.keymint.Algorithm;
import android.hardware.security.keymint.EcCurve;
import android.hardware.security.keymint.KeyOrigin;
import android.hardware.security.keymint.KeyParameter;
import android.hardware.security.keymint.Tag;
import android.os.Binder;
import android.os.Build;
import android.os.SystemProperties;
import android.os.UserHandle;
import android.provider.Settings;
import android.security.keystore.KeyProperties;
import android.system.keystore2.KeyDescriptor;
import android.util.Base64;
import android.util.Log;

import android.annotation.Nullable;

import com.android.internal.org.bouncycastle.asn1.ASN1Boolean;
import com.android.internal.org.bouncycastle.asn1.ASN1Encodable;
import com.android.internal.org.bouncycastle.asn1.ASN1Enumerated;
import com.android.internal.org.bouncycastle.asn1.ASN1Integer;
import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.internal.org.bouncycastle.asn1.ASN1OctetString;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.DERNull;
import com.android.internal.org.bouncycastle.asn1.DEROctetString;
import com.android.internal.org.bouncycastle.asn1.DERSequence;
import com.android.internal.org.bouncycastle.asn1.DERSet;
import com.android.internal.org.bouncycastle.asn1.DERTaggedObject;
import com.android.internal.org.bouncycastle.asn1.x500.X500Name;
import com.android.internal.org.bouncycastle.asn1.x509.Extension;
import com.android.internal.org.bouncycastle.asn1.x509.KeyUsage;
import com.android.internal.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.android.internal.org.bouncycastle.asn1.x509.Time;
import com.android.internal.org.bouncycastle.cert.X509CertificateHolder;
import com.android.internal.org.bouncycastle.cert.X509v3CertificateBuilder;
import com.android.internal.org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.android.internal.org.bouncycastle.operator.ContentSigner;
import com.android.internal.org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

/**
 * @hide
 */
public final class KeyboxChainGenerator {

    private static final String TAG = "KeyboxChainGenerator";
    private static final boolean DEBUG = Log.isLoggable(TAG, Log.DEBUG);

    private static final int ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX = 0;
    private static final int ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX = 1;
    private static final int ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX = 0;
    private static final int ATTESTATION_PACKAGE_INFO_VERSION_INDEX = 1;

    public static List<Certificate> generateCertChain(int uid, KeyDescriptor descriptor, KeyGenParameters params) {
        dlog("Requested KeyPair with alias: " + descriptor.alias);
        int size = params.keySize;
        KeyPair kp;
        try {
            if (Objects.equals(params.algorithm, Algorithm.EC)) {
                dlog("Generating EC keypair of size " + size);
                kp = buildECKeyPair(params);
            } else if (Objects.equals(params.algorithm, Algorithm.RSA)) {
                dlog("Generating RSA keypair of size " + size);
                kp = buildRSAKeyPair(params);
            } else {
                dlog("Unsupported algorithm");
                return null;
            }

            final String keyboxAlgorithm = Objects.equals(params.algorithm, Algorithm.EC)
                    ? KeyProperties.KEY_ALGORITHM_EC
                    : KeyProperties.KEY_ALGORITHM_RSA;
            X509CertificateHolder issuer = KeyboxUtils.getCertificateHolder(keyboxAlgorithm);
            if (issuer == null) {
                dlog("Keybox has no " + keyboxAlgorithm + " key, not spoofing");
                return null;
            }
            X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                    issuer.getSubject(),
                    params.certificateSerial,
                    new Time(params.certificateNotBefore),
                    new Time(params.certificateNotAfter),
                    params.certificateSubject,
                    SubjectPublicKeyInfo.getInstance(
                            ASN1Sequence.getInstance(kp.getPublic().getEncoded())
                    )
            );

            KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign);
            certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
            certBuilder.addExtension(createExtension(params, uid));

            PrivateKey signingKey = KeyboxUtils.getPrivateKey(keyboxAlgorithm);
            if (signingKey == null) {
                dlog("Keybox has no " + keyboxAlgorithm + " private key, not spoofing");
                return null;
            }
            ContentSigner contentSigner = Objects.equals(params.algorithm, Algorithm.EC)
                    ? new JcaContentSignerBuilder("SHA256withECDSA").build(signingKey)
                    : new JcaContentSignerBuilder("SHA256withRSA").build(signingKey);
            X509CertificateHolder certHolder = certBuilder.build(contentSigner);
            Certificate leaf = KeyboxUtils.getCertificateFromHolder(certHolder);
            List<Certificate> chain = KeyboxUtils.getCertificateChain(keyboxAlgorithm);
            if (chain == null) {
                return null;
            }
            chain.add(0, leaf);
            dlog("Successfully generated X500 Cert for alias: " + descriptor.alias);
            return chain;
        } catch (Throwable t) {
            Log.e(TAG, Log.getStackTraceString(t));
        }
        return null;
    }

    private static ASN1Encodable[] fromIntList(List<Integer> list) {
        ASN1Encodable[] result = new ASN1Encodable[list.size()];
        for (int i = 0; i < list.size(); i++) {
            result[i] = new ASN1Integer(list.get(i));
        }
        return result;
    }

    private static Extension createExtension(KeyGenParameters params, int uid) {
        try {
            Context context = ActivityThread.currentApplication();
            if (context == null) {
                Log.e(TAG, "Context is null in createExtension");
                return null;
            }
            SecureRandom secureRandom = new SecureRandom();
            
            String key = Settings.Secure.getString(context.getContentResolver(), Settings.Secure.VBOOT_KEY);
            byte[] verifiedBootKey;
            if (key == null) {
                byte[] randomBytes = new byte[32];
                secureRandom.nextBytes(randomBytes);
                String encoded = Base64.encodeToString(randomBytes, Base64.NO_WRAP);
                Settings.Secure.putString(context.getContentResolver(), Settings.Secure.VBOOT_KEY, encoded);
                verifiedBootKey = randomBytes;
            } else {
                verifiedBootKey = Base64.decode(key, Base64.NO_WRAP);
            }

            String hash = Settings.Secure.getString(context.getContentResolver(), Settings.Secure.VBOOT_HASH);
            byte[] verifiedBootHash;
            if (hash == null) {
                byte[] randomBytes = new byte[32];
                secureRandom.nextBytes(randomBytes);
                String encoded = Base64.encodeToString(randomBytes, Base64.NO_WRAP);
                Settings.Secure.putString(context.getContentResolver(), Settings.Secure.VBOOT_HASH, encoded);
                verifiedBootHash = randomBytes;
            } else {
                verifiedBootHash = Base64.decode(hash, Base64.NO_WRAP);
            }

            ASN1Encodable[] rootOfTrustEncodables = {
                    new DEROctetString(verifiedBootKey),
                    ASN1Boolean.TRUE,
                    new ASN1Enumerated(0),
                    new DEROctetString(verifiedBootHash)
            };

            ASN1Sequence rootOfTrustSeq = new DERSequence(rootOfTrustEncodables);

            var Apurpose = new DERSet(fromIntList(params.purpose));
            var Aalgorithm = new ASN1Integer(params.algorithm);
            var AkeySize = new ASN1Integer(params.keySize);
            var Adigest = new DERSet(fromIntList(params.digest));
            var AecCurve = new ASN1Integer(params.ecCurve);
            var AnoAuthRequired = DERNull.INSTANCE;
            var Aorigin = new ASN1Integer(0);

            // To be loaded
            var AosVersion = new ASN1Integer(getOsVersion());
            var AosPatchLevel = new ASN1Integer(getPatchLevel());
            var AbootPatchlevel = new ASN1Integer(getPatchLevelLong());
            var AvendorPatchLevel = new ASN1Integer(getPatchLevelLong());

            var purpose = new DERTaggedObject(true, 1, Apurpose);
            var algorithm = new DERTaggedObject(true, 2, Aalgorithm);
            var keySize = new DERTaggedObject(true, 3, AkeySize);
            var digest = new DERTaggedObject(true, 5, Adigest);
            var ecCurve = new DERTaggedObject(true, 10, AecCurve);
            var noAuthRequired = new DERTaggedObject(true, 503, AnoAuthRequired);
            var origin = new DERTaggedObject(true, 702, Aorigin);
            var rootOfTrust = new DERTaggedObject(true, 704, rootOfTrustSeq);
            var osVersion = new DERTaggedObject(true, 705, AosVersion);
            var osPatchLevel = new DERTaggedObject(true, 706, AosPatchLevel);
            var vendorPatchLevel = new DERTaggedObject(true, 718, AvendorPatchLevel);
            var bootPatchLevel = new DERTaggedObject(true, 719, AbootPatchlevel);

            ASN1Encodable[] teeEnforcedEncodables;

            // Support device properties attestation. The requested IDs describe the real
            // device (this runs in system_server), so replace them with the spoofed profile.
            if (params.brand != null) {
                var Abrand = new DEROctetString(idValue(params.brand, "BRAND"));
                var Adevice = new DEROctetString(idValue(params.device, "DEVICE"));
                var Aproduct = new DEROctetString(idValue(params.product, "PRODUCT"));
                var Amanufacturer = new DEROctetString(idValue(params.manufacturer, "MANUFACTURER"));
                var Amodel = new DEROctetString(idValue(params.model, "MODEL"));
                var brand = new DERTaggedObject(true, 710, Abrand);
                var device = new DERTaggedObject(true, 711, Adevice);
                var product = new DERTaggedObject(true, 712, Aproduct);
                var manufacturer = new DERTaggedObject(true, 716, Amanufacturer);
                var model = new DERTaggedObject(true, 717, Amodel);

                teeEnforcedEncodables = new ASN1Encodable[]{purpose, algorithm, keySize, digest, ecCurve,
                        noAuthRequired, origin, rootOfTrust, osVersion, osPatchLevel,
                        brand, device, product, manufacturer, model, vendorPatchLevel,
                        bootPatchLevel};
            } else {
                teeEnforcedEncodables = new ASN1Encodable[]{purpose, algorithm, keySize, digest, ecCurve,
                        noAuthRequired, origin, rootOfTrust, osVersion, osPatchLevel, vendorPatchLevel,
                        bootPatchLevel};
            }

            var AcreationDateTime = new ASN1Integer(System.currentTimeMillis());
            var AapplicationID = createApplicationId(uid);

            var creationDateTime = new DERTaggedObject(true, 701, AcreationDateTime);
            var applicationID = new DERTaggedObject(true, 709, AapplicationID);

            ASN1Encodable[] softwareEnforced = {creationDateTime, applicationID};

            ASN1OctetString keyDescriptionOctetStr = getAsn1OctetString(teeEnforcedEncodables, softwareEnforced, params);

            return new Extension(new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"), false, keyDescriptionOctetStr);
        } catch (Throwable t) {
            Log.e(TAG, Log.getStackTraceString(t));
        }
        return null;
    }

    private static int getOsVersion() {
        String release = profileValue("RELEASE");
        if (release == null) release = Build.VERSION.RELEASE;
        int major = 16, minor = 0, patch = 0;

        // Handle cases with additional suffixes like "/BP31"
        release = release.split("/")[0];

        String[] parts = release.split("\\.");
        try {
            if (parts.length > 0) major = Integer.parseInt(parts[0]);
            if (parts.length > 1) minor = Integer.parseInt(parts[1]);
            if (parts.length > 2) patch = Integer.parseInt(parts[2]);
        } catch (NumberFormatException e) {
            Log.w(TAG, "Unable to parse OS version: " + release);
        }

        return major * 10000 + minor * 100 + patch;
    }

    private static int getPatchLevel() {
        String patchLevel = profileValue("SECURITY_PATCH");
        return convertPatchLevel(patchLevel != null ? patchLevel : Build.VERSION.SECURITY_PATCH, false);
    }

    private static int getPatchLevelLong() {
        String patchLevel = profileValue("SECURITY_PATCH");
        return convertPatchLevel(patchLevel != null ? patchLevel : Build.VERSION.SECURITY_PATCH, true);
    }

    private static final String PIHOOKS_PREFIX = "persist.sys.pihooks_";

    /** Same fallback the in-process hooks use when the resource array is unavailable. */
    private static final String[] FALLBACK_PROFILE = {
            "BRAND:google",
            "DEVICE:caiman",
            "PRODUCT:caiman_beta",
            "MANUFACTURER:Google",
            "MODEL:Pixel 9 Pro",
            "RELEASE:16",
            "SECURITY_PATCH:2025-10-05",
    };

    private static HashMap<String, String> sProfile;

    private static synchronized HashMap<String, String> getProfile() {
        if (sProfile != null) return sProfile;
        HashMap<String, String> profile = new HashMap<>();
        try {
            for (String entry : Resources.getSystem().getStringArray(
                    com.android.internal.R.array.config_certifiedBuildProperties)) {
                putProfileEntry(profile, entry);
            }
        } catch (Exception e) {
            Log.w(TAG, "Certified build properties not available", e);
        }
        for (String entry : FALLBACK_PROFILE) {
            putProfileEntry(profile, entry);
        }
        sProfile = profile;
        return profile;
    }

    private static void putProfileEntry(HashMap<String, String> profile, String entry) {
        int split = entry.indexOf(':');
        if (split <= 0) return;
        String key = entry.substring(0, split).trim();
        if (key.startsWith("VERSION.")) key = key.substring("VERSION.".length());
        profile.putIfAbsent(key, entry.substring(split + 1).trim());
    }

    /** Value of the spoofed build profile, or null if neither a PIF nor the fallback has it. */
    private static String profileValue(String key) {
        String value = SystemProperties.get(PIHOOKS_PREFIX + key, "");
        if (value.isEmpty()) {
            value = SystemProperties.get(PIHOOKS_PREFIX + "VERSION." + key, "");
        }
        return value.isEmpty() ? getProfile().get(key) : value;
    }

    private static byte[] idValue(byte[] requested, String key) {
        String value = profileValue(key);
        return value == null ? requested : value.getBytes(StandardCharsets.UTF_8);
    }

    private static int convertPatchLevel(String patchLevel, boolean longFormat) {
        try {
            String[] parts = patchLevel.split("-");
            int year = Integer.parseInt(parts[0]);
            int month = Integer.parseInt(parts[1]);
            if (longFormat) {
                int day = Integer.parseInt(parts[2]);
                return year * 10000 + month * 100 + day;
            } else {
                return year * 100 + month;
            }
        } catch (Exception e) {
            Log.e(TAG, "Invalid patch level: " + patchLevel, e);
            return 202404;
        }
    }

    private static ASN1OctetString getAsn1OctetString(ASN1Encodable[] teeEnforcedEncodables, ASN1Encodable[] softwareEnforcedEncodables, KeyGenParameters params) throws IOException {
        ASN1Integer attestationVersion = new ASN1Integer(100);
        ASN1Enumerated attestationSecurityLevel = new ASN1Enumerated(1);
        ASN1Integer keymasterVersion = new ASN1Integer(100);
        ASN1Enumerated keymasterSecurityLevel = new ASN1Enumerated(1);
        ASN1OctetString attestationChallenge = new DEROctetString(params.attestationChallenge);
        ASN1OctetString uniqueId = new DEROctetString(new byte[0]);
        ASN1Encodable softwareEnforced = new DERSequence(softwareEnforcedEncodables);
        ASN1Sequence teeEnforced = new DERSequence(teeEnforcedEncodables);

        ASN1Encodable[] keyDescriptionEncodables = {attestationVersion, attestationSecurityLevel, keymasterVersion,
                keymasterSecurityLevel, attestationChallenge, uniqueId, softwareEnforced, teeEnforced};

        ASN1Sequence keyDescriptionHackSeq = new DERSequence(keyDescriptionEncodables);

        return new DEROctetString(keyDescriptionHackSeq);
    }

    private static DEROctetString createApplicationId(int uid) throws Throwable {
        Context context = ActivityThread.currentApplication();
        if (context == null) {
            throw new IllegalStateException("createApplicationId: context not available from ActivityThread!");
        }

        PackageManager pm = context.getPackageManager();
        if (pm == null) {
            throw new IllegalStateException("createApplicationId: PackageManager not found!");
        }

        String[] packages = pm.getPackagesForUid(uid);
        if (packages == null || packages.length == 0) {
            throw new IllegalStateException("No packages found for UID: " + uid);
        }

        int size = packages.length;
        ASN1Encodable[] packageInfoAA = new ASN1Encodable[size];
        Set<Digest> signatures = new HashSet<>();
        MessageDigest dg = MessageDigest.getInstance("SHA-256");

        for (int i = 0; i < size; i++) {
            String name = packages[i];
            PackageInfo info = pm.getPackageInfo(name, PackageManager.GET_SIGNATURES);
            ASN1Encodable[] arr = new ASN1Encodable[2];
            arr[ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX] =
                    new DEROctetString(name.getBytes(StandardCharsets.UTF_8));
            arr[ATTESTATION_PACKAGE_INFO_VERSION_INDEX] =
                    new ASN1Integer(info.getLongVersionCode());
            packageInfoAA[i] = new DERSequence(arr);

            if (info != null && info.signatures != null) {
                for (Signature s : info.signatures) {
                    if (s != null) signatures.add(new Digest(dg.digest(s.toByteArray())));
                }
            }
        }

        ASN1Encodable[] signaturesAA = new ASN1Encodable[signatures.size()];
        int i = 0;
        for (Digest d : signatures) {
            signaturesAA[i++] = new DEROctetString(d.getDigest());
        }

        ASN1Encodable[] applicationIdAA = new ASN1Encodable[2];
        applicationIdAA[ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX] =
                new DERSet(packageInfoAA);
        applicationIdAA[ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX] =
                new DERSet(signaturesAA);

        return new DEROctetString(new DERSequence(applicationIdAA).getEncoded());
    }

    public static final class Digest {
        private final byte[] digest;

        public Digest(byte[] digest) {
            this.digest = digest;
        }

        public byte[] getDigest() {
            return digest;
        }

        @Override
        public boolean equals(@Nullable Object o) {
            if (o instanceof Digest) {
                Digest d = (Digest) o;
                return Arrays.equals(digest, d.digest);
            }
            return false;
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(digest);
        }
    }

    private static KeyPair buildECKeyPair(KeyGenParameters params) throws Exception {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.addProvider(new BouncyCastleProvider());
        ECGenParameterSpec spec = new ECGenParameterSpec(params.ecCurveName);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(spec);
        return kpg.generateKeyPair();
    }

    private static KeyPair buildRSAKeyPair(KeyGenParameters params) throws Exception {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.addProvider(new BouncyCastleProvider());
        RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(
                params.keySize, params.rsaPublicExponent);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(spec);
        return kpg.generateKeyPair();
    }

    private static void dlog(String msg) {
        if (DEBUG) Log.d(TAG, msg);
    }

    public static class KeyGenParameters {
        public int keySize;
        public int algorithm;
        public BigInteger certificateSerial;
        public Date certificateNotBefore;
        public Date certificateNotAfter;
        public X500Name certificateSubject;

        public BigInteger rsaPublicExponent;
        public int ecCurve;
        public String ecCurveName;

        public List<Integer> purpose = new ArrayList<>();
        public List<Integer> digest = new ArrayList<>();

        public byte[] attestationChallenge;
        public byte[] brand;
        public byte[] device;
        public byte[] product;
        public byte[] manufacturer;
        public byte[] model;

        public int securityLevel;
        public boolean noAuthRequired;

        // Extra fields for response metadata
        public int osVersion = KeyboxChainGenerator.getOsVersion();
        public int osPatchLevel = KeyboxChainGenerator.getPatchLevel();
        public int vendorPatchLevel = KeyboxChainGenerator.getPatchLevelLong();
        public int bootPatchLevel = KeyboxChainGenerator.getPatchLevelLong();
        public long creationDateTime = System.currentTimeMillis();
        public int userId = UserHandle.myUserId();
        public int origin = KeyOrigin.GENERATED;

        public KeyGenParameters(KeyParameter[] params) {
            for (KeyParameter kp : params) {
                switch (kp.tag) {
                    case Tag.KEY_SIZE:
                        keySize = kp.value.getInteger();
                        break;
                    case Tag.ALGORITHM:
                        algorithm = kp.value.getAlgorithm();
                        break;
                    case Tag.CERTIFICATE_SERIAL:
                        certificateSerial = new BigInteger(kp.value.getBlob());
                        break;
                    case Tag.CERTIFICATE_NOT_BEFORE:
                        certificateNotBefore = new Date(kp.value.getDateTime());
                        break;
                    case Tag.CERTIFICATE_NOT_AFTER:
                        certificateNotAfter = new Date(kp.value.getDateTime());
                        break;
                    case Tag.CERTIFICATE_SUBJECT:
                        certificateSubject =
                                new X500Name(new X500Principal(kp.value.getBlob()).getName());
                        break;
                    case Tag.RSA_PUBLIC_EXPONENT:
                        rsaPublicExponent = BigInteger.valueOf(kp.value.getLongInteger());
                        break;
                    case Tag.EC_CURVE:
                        ecCurve = kp.value.getEcCurve();
                        ecCurveName = getEcCurveName(ecCurve);
                        break;
                    case Tag.PURPOSE:
                        purpose.add(kp.value.getKeyPurpose());
                        break;
                    case Tag.DIGEST:
                        digest.add(kp.value.getDigest());
                        break;
                    case Tag.ATTESTATION_CHALLENGE:
                        attestationChallenge = kp.value.getBlob();
                        break;
                    case Tag.ATTESTATION_ID_BRAND:
                        brand = kp.value.getBlob();
                        break;
                    case Tag.ATTESTATION_ID_DEVICE:
                        device = kp.value.getBlob();
                        break;
                    case Tag.ATTESTATION_ID_PRODUCT:
                        product = kp.value.getBlob();
                        break;
                    case Tag.ATTESTATION_ID_MANUFACTURER:
                        manufacturer = kp.value.getBlob();
                        break;
                    case Tag.ATTESTATION_ID_MODEL:
                        model = kp.value.getBlob();
                        break;
                    case Tag.HARDWARE_TYPE:
                        securityLevel = kp.value.getSecurityLevel();
                        break;
                    case Tag.NO_AUTH_REQUIRED:
                        noAuthRequired = kp.value.getBoolValue();
                        break;
                }
            }
        }

        private static String getEcCurveName(int curve) {
            switch (curve) {
                case EcCurve.CURVE_25519:
                    return "CURVE_25519";
                case EcCurve.P_224:
                    return "secp224r1";
                case EcCurve.P_256:
                    return "secp256r1";
                case EcCurve.P_384:
                    return "secp384r1";
                case EcCurve.P_521:
                    return "secp521r1";
                default:
                    throw new IllegalArgumentException("unknown curve");
            }
        }
    }
}
