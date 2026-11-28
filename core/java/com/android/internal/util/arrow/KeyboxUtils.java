/*
 * SPDX-FileCopyrightText: 2025 Neoteric OS
 * SPDX-FileCopyrightText: 2025 Lunaris-AOSP
 * SPDX-FileCopyrightText: 2025 Project-PenguinOS
 * SPDX-License-Identifier: Apache-2.0
 *
 * Keybox parsing/chain handling adapted from Lunaris-AOSP frameworks_base (16.2)
 * and Project-PenguinOS KeyBoxManager/CertificateHacker.
 */
package com.android.internal.util.arrow;

import android.security.KeyStore2;
import android.security.keystore.KeyProperties;
import android.system.keystore2.KeyDescriptor;
import android.system.keystore2.KeyEntryResponse;
import android.system.keystore2.KeyMetadata;
import android.util.Log;

import com.android.internal.org.bouncycastle.asn1.ASN1Primitive;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.DERNull;
import com.android.internal.org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import com.android.internal.org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import com.android.internal.org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import com.android.internal.org.bouncycastle.asn1.sec.ECPrivateKey;
import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.android.internal.org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import com.android.internal.org.bouncycastle.cert.X509CertificateHolder;
import com.android.internal.org.bouncycastle.operator.ContentSigner;
import com.android.internal.org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @hide
 */
public class KeyboxUtils {

    private static final String TAG = "KeyboxUtils";

    private static final ConcurrentHashMap<Key, KeyEntryResponse> response = new ConcurrentHashMap<>();

    // Parsing the keybox PEM chain involves a private-key decode and a signature
    // round-trip per certificate, so cache the result for the provider instance.
    // KeyProviderManager returns a new provider when the keybox setting changes.
    private static final ConcurrentHashMap<String, Optional<Keybox>> sKeyboxSlots =
            new ConcurrentHashMap<>();
    private static final Object sKeyboxLock = new Object();
    private static volatile IKeyboxProvider sCachedKeyboxProvider;
    public static final class Key {
        public final int uid;
        public final String alias;

        public Key(int uid, String alias) {
            this.uid = uid;
            this.alias = alias;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof Key)) return false;
            Key key = (Key) o;
            return uid == key.uid && Objects.equals(alias, key.alias);
        }

        @Override
        public int hashCode() {
            return Objects.hash(uid, alias);
        }
    }

    /** Parsed keybox slot: the signing certificate comes first in the chain. */
    public static final class Keybox {
        public final String algorithm;
        public final PrivateKey privateKey;
        public final List<Certificate> certificates;

        Keybox(String algorithm, PrivateKey privateKey, List<Certificate> certificates) {
            this.algorithm = algorithm;
            this.privateKey = privateKey;
            this.certificates = certificates;
        }

        public X509Certificate signingCertificate() {
            return (X509Certificate) certificates.get(0);
        }
    }

    public static byte[] decodePemOrBase64(String input) {
        String base64 = input
                .replaceAll("-----BEGIN [^-]+-----", "")
                .replaceAll("-----END [^-]+-----", "")
                .replaceAll("\\s+", "");
        return Base64.getDecoder().decode(base64);
    }

    public static PrivateKey parsePrivateKey(String encodedKey, String algorithm) throws Exception {
        byte[] keyBytes = decodePemOrBase64(encodedKey);
        ASN1Primitive primitive = ASN1Primitive.fromByteArray(keyBytes);
        if ("EC".equalsIgnoreCase(algorithm)) {
            try {
                // Try parsing as PKCS#8
                PrivateKeyInfo info = PrivateKeyInfo.getInstance(primitive);
                return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(info.getEncoded()));
            } catch (Exception e) {
                // Possibly SEC1 / PKCS#1 EC
                ASN1Sequence seq = ASN1Sequence.getInstance(primitive);
                ECPrivateKey ecPrivateKey = ECPrivateKey.getInstance(seq);
                AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, ecPrivateKey.getParameters());
                PrivateKeyInfo privInfo = new PrivateKeyInfo(algId, ecPrivateKey);
                PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(privInfo.getEncoded());
                return KeyFactory.getInstance("EC").generatePrivate(pkcs8Spec);
            }
        } else if ("RSA".equalsIgnoreCase(algorithm)) {
            try {
                // Try parsing as PKCS#8
                return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
            } catch (Exception e) {
                // Parse as PKCS#1
                RSAPrivateKey rsaKey = RSAPrivateKey.getInstance(primitive);
                AlgorithmIdentifier algId = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
                PrivateKeyInfo privInfo = new PrivateKeyInfo(algId, rsaKey);
                PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(privInfo.getEncoded());
                return KeyFactory.getInstance("RSA").generatePrivate(pkcs8Spec);
            }
        } else {
            throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }
    }

    public static X509Certificate parseCertificate(String encodedCert) throws Exception {
        byte[] certBytes = decodePemOrBase64(encodedCert);
        return (X509Certificate) CertificateFactory
                .getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certBytes));
    }

    public static List<Certificate> getCertificateChain(String algorithm) throws Exception {
        IKeyboxProvider provider = KeyProviderManager.getProvider();
        String[] certChainPem = KeyProperties.KEY_ALGORITHM_EC.equals(algorithm)
                ? provider.getEcCertificateChain()
                : provider.getRsaCertificateChain();

        if (certChainPem == null || certChainPem.length == 0) {
            return null;
        }

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        List<Certificate> certs = new ArrayList<>();

        for (String certPem : certChainPem) {
            certs.add(parseCertificate(certPem));
        }

        return certs;
    }

    /**
     * Returns the keybox slot able to sign for a subject key of {@code preferredAlgorithm}.
     * An X.509 issuer's key algorithm does not have to match the subject's, so fall back to
     * the other slot when the keybox only ships one algorithm (most ship EC only).
     */
    public static Keybox getSigningKeybox(String preferredAlgorithm) {
        IKeyboxProvider provider;
        try {
            provider = KeyProviderManager.getProvider();
        } catch (Exception e) {
            Log.e(TAG, "Unable to load keybox provider", e);
            return null;
        }

        if (provider != sCachedKeyboxProvider) {
            synchronized (sKeyboxLock) {
                if (provider != sCachedKeyboxProvider) {
                    sKeyboxSlots.clear();
                    sCachedKeyboxProvider = provider;
                }
            }
        }

        String first = "RSA".equalsIgnoreCase(preferredAlgorithm) ? "RSA" : "EC";
        String second = "RSA".equals(first) ? "EC" : "RSA";
        Keybox keybox = getKeyboxSlot(provider, first);
        if (keybox == null) {
            keybox = getKeyboxSlot(provider, second);
        }
        return keybox;
    }

    private static Keybox getKeyboxSlot(IKeyboxProvider provider, String algorithm) {
        return sKeyboxSlots.computeIfAbsent(algorithm,
                alg -> Optional.ofNullable(parseKeyboxSlot(provider, alg))).orElse(null);
    }

    private static Keybox parseKeyboxSlot(IKeyboxProvider provider, String algorithm) {
        try {
            boolean ec = "EC".equals(algorithm);
            String privateKeyPem = ec
                    ? provider.getEcPrivateKey() : provider.getRsaPrivateKey();
            String[] chainPem = ec
                    ? provider.getEcCertificateChain() : provider.getRsaCertificateChain();
            if (privateKeyPem == null || chainPem == null || chainPem.length == 0) {
                return null;
            }

            PrivateKey privateKey = parsePrivateKey(privateKeyPem, algorithm);
            List<X509Certificate> certificates = new ArrayList<>();
            for (String pem : chainPem) {
                certificates.add(parseCertificate(pem));
            }

            X509Certificate signer = findSigningCertificate(privateKey, algorithm, certificates);
            if (signer == null) {
                Log.e(TAG, "Keybox slot " + algorithm + " private key matches no certificate");
                return null;
            }

            List<Certificate> ordered = Collections.unmodifiableList(
                    orderChain(signer, certificates));
            if (ordered.isEmpty()) return null;

            Log.i(TAG, "Keybox slot=" + algorithm + " certs=" + ordered.size()
                    + " signer=" + signer.getSubjectX500Principal().getName()
                    + " issuer=" + signer.getIssuerX500Principal().getName());
            return new Keybox(algorithm, privateKey, ordered);
        } catch (Exception e) {
            Log.e(TAG, "Invalid keybox slot " + algorithm, e);
            return null;
        }
    }

    private static X509Certificate findSigningCertificate(PrivateKey privateKey,
            String algorithm, List<X509Certificate> certificates) {
        X509Certificate match = null;
        for (X509Certificate certificate : certificates) {
            if (!privateKeyMatchesCertificate(privateKey, algorithm, certificate)) continue;
            if (match != null) {
                Log.w(TAG, "Multiple keybox certificates match the private key, using the first");
                break;
            }
            match = certificate;
        }
        return match;
    }

    private static boolean privateKeyMatchesCertificate(PrivateKey privateKey, String algorithm,
            X509Certificate certificate) {
        try {
            String sigAlg = "EC".equalsIgnoreCase(algorithm)
                    ? "SHA256withECDSA" : "SHA256withRSA";
            byte[] challenge = "keybox-key-match".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            Signature signer = Signature.getInstance(sigAlg);
            signer.initSign(privateKey);
            signer.update(challenge);
            byte[] signature = signer.sign();

            Signature verifier = Signature.getInstance(sigAlg);
            verifier.initVerify(certificate.getPublicKey());
            verifier.update(challenge);
            return verifier.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Keybox XML certificate order is not guaranteed. Walk from the certificate that
     * matches the private key towards its issuer, verifying every link.
     */
    private static List<Certificate> orderChain(X509Certificate signer,
            List<X509Certificate> certificates) throws Exception {
        List<X509Certificate> unique = new ArrayList<>();
        for (X509Certificate certificate : certificates) {
            boolean duplicate = false;
            for (X509Certificate existing : unique) {
                if (Arrays.equals(existing.getEncoded(), certificate.getEncoded())) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) unique.add(certificate);
        }

        List<Certificate> ordered = new ArrayList<>();
        List<X509Certificate> remaining = new ArrayList<>(unique);
        X509Certificate current = signer;
        while (current != null) {
            ordered.add(current);
            remaining.remove(current);

            if (current.getSubjectX500Principal().equals(current.getIssuerX500Principal())) {
                try {
                    current.verify(current.getPublicKey());
                    break;
                } catch (Exception ignored) {
                    // Self-issued but not self-signed (cross-signed rotation).
                }
            }

            X509Certificate next = null;
            for (X509Certificate candidate : remaining) {
                if (!current.getIssuerX500Principal()
                        .equals(candidate.getSubjectX500Principal())) {
                    continue;
                }
                try {
                    current.verify(candidate.getPublicKey());
                } catch (Exception ignored) {
                    continue;
                }
                if (next != null) {
                    Log.w(TAG, "Ambiguous keybox issuer, using the first matching certificate");
                    break;
                }
                next = candidate;
            }
            current = next;
        }

        if (!remaining.isEmpty()) {
            Log.w(TAG, "Ignoring " + remaining.size()
                    + " keybox certificate(s) not connected to the signing certificate");
        }
        return ordered;
    }

    public static ContentSigner createContentSigner(String algorithm, PrivateKey privateKey)
            throws Exception {
        return new JcaContentSignerBuilder(algorithm).build(privateKey);
    }

    public static void putCertificateChain(KeyEntryResponse response, Certificate[] chain) throws Exception {
        putCertificateChain(response.metadata, chain);
    }

    public static void putCertificateChain(KeyMetadata metadata, Certificate[] chain) throws Exception {
        metadata.certificate = chain[0].getEncoded();
        var output = new ByteArrayOutputStream();
        for (int i = 1; i < chain.length; i++) {
            output.write(chain[i].getEncoded());
        }
        metadata.certificateChain = output.toByteArray();
    }

    /** Parse the leaf plus the concatenated CA chain stored in KeyMetadata. */
    public static Certificate[] getCertificateChain(KeyMetadata metadata) throws Exception {
        if (metadata == null) return new Certificate[0];
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        List<Certificate> chain = new ArrayList<>();
        if (metadata.certificate != null && metadata.certificate.length > 0) {
            chain.add(factory.generateCertificate(
                    new ByteArrayInputStream(metadata.certificate)));
        }
        if (metadata.certificateChain != null && metadata.certificateChain.length > 0) {
            chain.addAll(factory.generateCertificates(
                    new ByteArrayInputStream(metadata.certificateChain)));
        }
        return chain.toArray(new Certificate[0]);
    }

    /**
     * Persist a hacked chain into keystore2 so every later getKeyEntry returns the
     * same leaf and the TEE private key keeps working. Best effort.
     */
    public static boolean persistCertificateChain(KeyDescriptor key, Certificate[] chain) {
        try {
            if (key == null || chain == null || chain.length == 0) return false;
            byte[] publicCert = chain[0].getEncoded();
            byte[] certificateChain = null;
            if (chain.length > 1) {
                ByteArrayOutputStream output = new ByteArrayOutputStream();
                for (int i = 1; i < chain.length; i++) {
                    output.write(chain[i].getEncoded());
                }
                certificateChain = output.toByteArray();
            }
            KeyStore2.getInstance().updateSubcomponents(key, publicCert, certificateChain);
            return true;
        } catch (Exception e) {
            Log.w(TAG, "Unable to persist hacked certificate chain", e);
            return false;
        }
    }

    public static Certificate getCertificateFromHolder(X509CertificateHolder holder) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return certFactory.generateCertificate(
                new ByteArrayInputStream(holder.getEncoded()));
    }

    public static PrivateKey getPrivateKey(String algorithm) throws Exception {
        Keybox keybox = getSigningKeybox(algorithm);
        return keybox == null ? null : keybox.privateKey;
    }

    public static X509CertificateHolder getCertificateHolder(String algorithm) throws Exception {
        Keybox keybox = getSigningKeybox(algorithm);
        if (keybox == null) return null;
        return new X509CertificateHolder(keybox.certificates.get(0).getEncoded());
    }

    public static void append(int uid, String a, KeyEntryResponse c) {
        response.put(new Key(uid, a), c);
    }

    public static void remove(int uid, String a) {
        response.remove(new Key(uid, a));
    }

    public static KeyEntryResponse retrieve(int uid, String a) {
        return response.get(new Key(uid, a));
    }
}
