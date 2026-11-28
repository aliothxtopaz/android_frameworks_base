/*
 * SPDX-FileCopyrightText: 2025 Lunaris-AOSP
 * SPDX-FileCopyrightText: 2025 Project-PenguinOS
 * SPDX-License-Identifier: Apache-2.0
 *
 * Adapted from Lunaris-AOSP frameworks_base (16.2) CertificateHacker and
 * Project-PenguinOS frameworks_base trickystore CertificateHacker.
 */
package com.android.internal.util.arrow;

import android.hardware.security.keymint.SecurityLevel;
import android.util.Log;

import com.android.internal.org.bouncycastle.asn1.ASN1Boolean;
import com.android.internal.org.bouncycastle.asn1.ASN1Encodable;
import com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector;
import com.android.internal.org.bouncycastle.asn1.ASN1Enumerated;
import com.android.internal.org.bouncycastle.asn1.ASN1Integer;
import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.internal.org.bouncycastle.asn1.ASN1OctetString;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.ASN1TaggedObject;
import com.android.internal.org.bouncycastle.asn1.DEROctetString;
import com.android.internal.org.bouncycastle.asn1.DERSequence;
import com.android.internal.org.bouncycastle.asn1.DERTaggedObject;
import com.android.internal.org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import com.android.internal.org.bouncycastle.asn1.x509.Extension;
import com.android.internal.org.bouncycastle.asn1.x509.Extensions;
import com.android.internal.org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import com.android.internal.org.bouncycastle.cert.X509CertificateHolder;
import com.android.internal.org.bouncycastle.cert.X509v3CertificateBuilder;
import com.android.internal.org.bouncycastle.operator.ContentSigner;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Rewrites the leaf of a real TEE attestation chain with a keybox-signed leaf.
 *
 * The leaf's public key is preserved, so the keystore private key keeps working.
 * Only the attestation extension (RootOfTrust, OS/patch levels, attestation IDs)
 * is replaced; the issuer changes to the keybox certificate.
 *
 * @hide
 */
public final class KeyboxCertificateHacker {
    private static final String TAG = "KeyboxCertificateHacker";
    private static final boolean DEBUG = Log.isLoggable(TAG, Log.DEBUG);

    public static final ASN1ObjectIdentifier ATTESTATION_OID =
            new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17");

    private static final int TAG_ROOT_OF_TRUST = 704;
    private static final int TAG_OS_VERSION = 705;
    private static final int TAG_OS_PATCHLEVEL = 706;
    private static final int TAG_ATTESTATION_ID_BRAND = 710;
    private static final int TAG_ATTESTATION_ID_DEVICE = 711;
    private static final int TAG_ATTESTATION_ID_PRODUCT = 712;
    private static final int TAG_ATTESTATION_ID_MANUFACTURER = 716;
    private static final int TAG_ATTESTATION_ID_MODEL = 717;
    private static final int TAG_VENDOR_PATCHLEVEL = 718;
    private static final int TAG_BOOT_PATCHLEVEL = 719;

    private KeyboxCertificateHacker() {}

    /**
     * @return the hacked chain (leaf + keybox chain), or {@code chain} when there is
     *         nothing to do / the hack failed. Never returns null for a non-null input.
     */
    public static Certificate[] hackCertificateChain(String alias, Certificate[] chain) {
        if (chain == null || chain.length == 0) return chain;

        try {
            if (!(chain[0] instanceof X509Certificate)) return chain;
            X509Certificate leaf = (X509Certificate) chain[0];

            X509CertificateHolder leafHolder = new X509CertificateHolder(leaf.getEncoded());
            Extension extension = leafHolder.getExtension(ATTESTATION_OID);
            if (extension == null) {
                dlog(alias, "leaf has no attestation extension, leaving chain untouched");
                return chain;
            }

            ASN1Sequence sequence =
                    ASN1Sequence.getInstance(extension.getExtnValue().getOctets());
            if (sequence.size() != 8) {
                Log.w(TAG, "Unexpected KeyDescription size for " + alias + ": " + sequence.size());
                return chain;
            }

            int securityLevel = ASN1Enumerated.getInstance(sequence.getObjectAt(3))
                    .getValue().intValue();
            if (securityLevel == SecurityLevel.STRONGBOX) {
                dlog(alias, "StrongBox attestation, leaving chain untouched");
                return chain;
            }

            KeyboxUtils.Keybox keybox = KeyboxUtils.getSigningKeybox(
                    leaf.getPublicKey().getAlgorithm());
            if (keybox == null) {
                Log.e(TAG, "No signing keybox for " + alias);
                return chain;
            }

            if (isSignedByKeybox(chain, leaf, keybox)) {
                dlog(alias, "chain is already signed by the active keybox");
                return chain;
            }

            ASN1Encodable[] keyDescription = sequence.toArray();
            ASN1Sequence teeEnforced = ASN1Sequence.getInstance(keyDescription[7]);
            Map<Integer, byte[]> attestationIdOverrides = getAttestationIdOverrides();

            ASN1EncodableVector kept = new ASN1EncodableVector();
            ASN1Sequence originalRootOfTrust = null;
            for (ASN1Encodable element : teeEnforced) {
                ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(element);
                int tag = tagged.getTagNo();
                if (tag == TAG_ROOT_OF_TRUST) {
                    originalRootOfTrust = ASN1Sequence.getInstance(tagged.getObject());
                } else if (tag == TAG_OS_VERSION || tag == TAG_OS_PATCHLEVEL
                        || tag == TAG_VENDOR_PATCHLEVEL || tag == TAG_BOOT_PATCHLEVEL) {
                    // Replaced below.
                } else if (attestationIdOverrides.containsKey(tag)) {
                    // Replaced below so the certified identity matches the Build fields.
                } else {
                    kept.add(tagged);
                }
            }

            byte[] bootKey = rootOfTrustOctet(originalRootOfTrust, 0);
            if (KeyboxAttestationUtils.isNullOrZero(bootKey)) {
                bootKey = KeyboxAttestationUtils.getBootKey();
            }
            byte[] bootHash = rootOfTrustOctet(originalRootOfTrust, 3);
            if (KeyboxAttestationUtils.isNullOrZero(bootHash)) {
                bootHash = KeyboxAttestationUtils.getBootHash();
            }
            boolean hasBootHash = originalRootOfTrust == null
                    || originalRootOfTrust.size() >= 4;

            ASN1EncodableVector rootOfTrust = new ASN1EncodableVector();
            rootOfTrust.add(new DEROctetString(bootKey));
            rootOfTrust.add(ASN1Boolean.TRUE);
            rootOfTrust.add(new ASN1Enumerated(0));
            if (hasBootHash) {
                rootOfTrust.add(new DEROctetString(bootHash));
            }

            int osVersion = KeyboxChainGenerator.getOsVersion();
            int osPatchLevel = KeyboxChainGenerator.getPatchLevel();
            int vendorPatchLevel = KeyboxChainGenerator.getPatchLevelLong();
            int bootPatchLevel = vendorPatchLevel;

            // KeyMint emits AuthorizationList tags in ascending order.
            TreeMap<Integer, ASN1Encodable> ordered = new TreeMap<>();
            for (int i = 0; i < kept.size(); i++) {
                ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(kept.get(i));
                ordered.put(tagged.getTagNo(), tagged);
            }
            ordered.put(TAG_OS_VERSION,
                    new DERTaggedObject(true, TAG_OS_VERSION, new ASN1Integer(osVersion)));
            ordered.put(TAG_OS_PATCHLEVEL,
                    new DERTaggedObject(true, TAG_OS_PATCHLEVEL, new ASN1Integer(osPatchLevel)));
            ordered.put(TAG_VENDOR_PATCHLEVEL,
                    new DERTaggedObject(true, TAG_VENDOR_PATCHLEVEL,
                            new ASN1Integer(vendorPatchLevel)));
            ordered.put(TAG_BOOT_PATCHLEVEL,
                    new DERTaggedObject(true, TAG_BOOT_PATCHLEVEL,
                            new ASN1Integer(bootPatchLevel)));
            ordered.put(TAG_ROOT_OF_TRUST,
                    new DERTaggedObject(TAG_ROOT_OF_TRUST,
                            new DERSequence(rootOfTrust)));
            for (Map.Entry<Integer, byte[]> entry : attestationIdOverrides.entrySet()) {
                ordered.put(entry.getKey(), new DERTaggedObject(true, entry.getKey(),
                        new DEROctetString(entry.getValue())));
            }

            ASN1EncodableVector hackedTee = new ASN1EncodableVector();
            for (ASN1Encodable encodable : ordered.values()) {
                hackedTee.add(encodable);
            }
            keyDescription[7] = new DERSequence(hackedTee);

            Extension hackedExtension = new Extension(ATTESTATION_OID, false,
                    new DEROctetString(new DERSequence(keyDescription).getEncoded()));

            X509CertificateHolder issuerHolder = new X509CertificateHolder(
                    keybox.certificates.get(0).getEncoded());
            X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                    issuerHolder.getSubject(),
                    leafHolder.getSerialNumber(),
                    leafHolder.getNotBefore(),
                    leafHolder.getNotAfter(),
                    leafHolder.getSubject(),
                    leafHolder.getSubjectPublicKeyInfo());

            Extensions extensions = leafHolder.getExtensions();
            if (extensions == null) {
                builder.addExtension(hackedExtension);
            } else {
                for (ASN1ObjectIdentifier oid : extensions.getExtensionOIDs()) {
                    if (ATTESTATION_OID.equals(oid)) {
                        builder.addExtension(hackedExtension);
                    } else if (Extension.authorityKeyIdentifier.equals(oid)) {
                        builder.addExtension(Extension.authorityKeyIdentifier,
                                extensions.getExtension(oid).isCritical(),
                                buildAuthorityKeyIdentifier(issuerHolder));
                    } else {
                        builder.addExtension(extensions.getExtension(oid));
                    }
                }
            }

            String signatureAlgorithm = "EC".equalsIgnoreCase(keybox.privateKey.getAlgorithm())
                    ? "SHA256withECDSA" : "SHA256withRSA";
            ContentSigner signer = KeyboxUtils.createContentSigner(
                    signatureAlgorithm, keybox.privateKey);
            X509CertificateHolder builtHolder = builder.build(signer);

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate hackedLeaf = (X509Certificate) certFactory.generateCertificate(
                    new ByteArrayInputStream(builtHolder.getEncoded()));

            hackedLeaf.verify(((X509Certificate) keybox.certificates.get(0)).getPublicKey());
            if (!Arrays.equals(hackedLeaf.getPublicKey().getEncoded(),
                    leaf.getPublicKey().getEncoded())) {
                throw new IllegalStateException("Hacked leaf public key changed");
            }

            List<Certificate> result = new ArrayList<>();
            result.add(hackedLeaf);
            result.addAll(keybox.certificates);

            Log.i(TAG, "leaf-hacked chain for " + alias
                    + " slot=" + keybox.algorithm
                    + " keyboxCerts=" + keybox.certificates.size()
                    + " issuer=" + issuerHolder.getSubject()
                    + " leafAlg=" + leaf.getPublicKey().getAlgorithm()
                    + " os=" + osVersion
                    + " patch=" + osPatchLevel
                    + " vendorPatch=" + vendorPatchLevel
                    + " bootPatch=" + bootPatchLevel);
            return result.toArray(new Certificate[0]);
        } catch (Exception e) {
            Log.e(TAG, "Failed to hack certificate chain for " + alias, e);
            return chain;
        }
    }

    private static AuthorityKeyIdentifier buildAuthorityKeyIdentifier(
            X509CertificateHolder issuerHolder) throws Exception {
        Extension subjectKeyId = issuerHolder.getExtension(Extension.subjectKeyIdentifier);
        byte[] issuerKeyId = subjectKeyId != null
                ? SubjectKeyIdentifier.getInstance(subjectKeyId.getParsedValue()).getKeyIdentifier()
                : MessageDigest.getInstance("SHA-1").digest(
                        issuerHolder.getSubjectPublicKeyInfo().getPublicKeyData().getBytes());
        return new AuthorityKeyIdentifier(issuerKeyId);
    }

    private static boolean isSignedByKeybox(Certificate[] chain, X509Certificate leaf,
            KeyboxUtils.Keybox keybox) {
        List<Certificate> certificates = keybox.certificates;
        if (chain.length != certificates.size() + 1) return false;
        try {
            for (int i = 0; i < certificates.size(); i++) {
                if (!Arrays.equals(chain[i + 1].getEncoded(),
                        certificates.get(i).getEncoded())) {
                    return false;
                }
            }
            X509Certificate issuer = (X509Certificate) certificates.get(0);
            if (!leaf.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                return false;
            }
            leaf.verify(issuer.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static Map<Integer, byte[]> getAttestationIdOverrides() {
        Map<Integer, byte[]> overrides = new HashMap<>();
        putIfPresent(overrides, TAG_ATTESTATION_ID_BRAND,
                KeyboxChainGenerator.getProfileValue("BRAND"));
        putIfPresent(overrides, TAG_ATTESTATION_ID_DEVICE,
                KeyboxChainGenerator.getProfileValue("DEVICE"));
        putIfPresent(overrides, TAG_ATTESTATION_ID_PRODUCT,
                KeyboxChainGenerator.getProfileValue("PRODUCT"));
        putIfPresent(overrides, TAG_ATTESTATION_ID_MANUFACTURER,
                KeyboxChainGenerator.getProfileValue("MANUFACTURER"));
        putIfPresent(overrides, TAG_ATTESTATION_ID_MODEL,
                KeyboxChainGenerator.getProfileValue("MODEL"));
        return overrides;
    }

    private static void putIfPresent(Map<Integer, byte[]> map, int tag, String value) {
        if (value != null && !value.isEmpty()) {
            map.put(tag, value.getBytes(StandardCharsets.UTF_8));
        }
    }

    private static byte[] rootOfTrustOctet(ASN1Sequence rootOfTrust, int index) {
        try {
            if (rootOfTrust == null || rootOfTrust.size() <= index) return null;
            ASN1OctetString value = ASN1OctetString.getInstance(
                    rootOfTrust.getObjectAt(index));
            byte[] octets = value.getOctets();
            return octets.length == 0 ? null : octets;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static void dlog(String alias, String message) {
        if (DEBUG) Log.d(TAG, alias + ": " + message);
    }
}
