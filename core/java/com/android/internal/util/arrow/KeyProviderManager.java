/*
 * SPDX-FileCopyrightText: 2024 Paranoid Android
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.internal.util.arrow;

import android.app.ActivityThread;
import android.content.Context;
import android.provider.Settings;
import android.util.Log;
import android.util.Xml;

import com.android.internal.R;
import org.xmlpull.v1.XmlPullParser;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Manager class for handling keybox providers.
 * @hide
 */
public final class KeyProviderManager {
    private static final String TAG = "KeyProviderManager";

    // Avoid spamming logcat; getProvider() is called for every attestation.
    private static volatile String sLastSummary;

    private KeyProviderManager() {}

    // Avoid re-parsing the keybox XML for every keystore operation.
    private static volatile String sCachedXml;
    private static volatile IKeyboxProvider sCachedProvider;

    public static IKeyboxProvider getProvider() {
        Context context = getApplicationContext();
        String xml = null;
        if (context != null) {
            try {
                xml = Settings.Secure.getString(
                        context.getContentResolver(), Settings.Secure.KEYBOX_DATA);
            } catch (Exception e) {
                Log.e(TAG, "Failed to read keybox setting", e);
            }
        }

        IKeyboxProvider cached = sCachedProvider;
        if (cached != null && java.util.Objects.equals(xml, sCachedXml)) {
            return cached;
        }

        DefaultKeyboxProvider provider = new DefaultKeyboxProvider(context, xml);
        sCachedXml = xml;
        sCachedProvider = provider;
        return provider;
    }

    public static boolean isKeyboxAvailable() {
        return getProvider().hasKeybox();
    }

    private static Context getApplicationContext() {
        try {
            return ActivityThread.currentApplication().getApplicationContext();
        } catch (Exception e) {
            Log.e(TAG, "Error getting application context", e);
            return null;
        }
    }

    private static class DefaultKeyboxProvider implements IKeyboxProvider {
        private final Map<String, String> keyboxData = new HashMap<>();

        private DefaultKeyboxProvider(Context context, String xml) {
            if (context == null) {
                Log.e(TAG, "Failed to get application context");
                return;
            }

            if (!loadFromXmlSetting(xml)) {
                loadFromConfigArray(context);
            }
        }

        private boolean loadFromXmlSetting(String xml) {
            try {
                if (xml == null || xml.trim().isEmpty()) return false;

                XmlPullParser p = Xml.newPullParser();
                p.setInput(new StringReader(xml));

                String currentAlg = null;
                int certCount = 0;
                boolean numberOfKeyboxesChecked = false;
                int declaredKeyboxes = -1;

                for (int ev = p.next(); ev != XmlPullParser.END_DOCUMENT; ev = p.next()) {
                    if (ev == XmlPullParser.START_TAG) {
                        String tag = p.getName();
                        switch (tag) {
                            case "NumberOfKeyboxes":
                                p.next();
                                numberOfKeyboxesChecked = true;
                                try {
                                    declaredKeyboxes = Integer.parseInt(p.getText().trim());
                                } catch (NumberFormatException e) {
                                    Log.w(TAG, "Failed to parse NumberOfKeyboxes", e);
                                }
                                break;

                            case "Key":
                                currentAlg = p.getAttributeValue(null, "algorithm");
                                if ("ecdsa".equalsIgnoreCase(currentAlg)) currentAlg = "EC";
                                else if ("rsa".equalsIgnoreCase(currentAlg)) currentAlg = "RSA";
                                else currentAlg = null;
                                certCount = 0;
                                // A later <Key> for the same algorithm replaces the slot;
                                // drop stale certificates from a previous <Keybox> block.
                                if (currentAlg != null) {
                                    keyboxData.remove(currentAlg + ".PRIV");
                                    for (int i = 1;
                                            keyboxData.remove(currentAlg + ".CERT_" + i) != null;
                                            i++) {
                                    }
                                }
                                break;

                            case "PrivateKey": {
                                String format = p.getAttributeValue(null, "format");
                                if (!"pem".equalsIgnoreCase(format)) {
                                    Log.w(TAG, "Unsupported PrivateKey format: " + format);
                                    return false;
                                }
                                p.next();
                                if (currentAlg != null) {
                                    keyboxData.put(currentAlg + ".PRIV", p.getText().trim());
                                }
                                break;
                            }

                            case "Certificate": {
                                String format = p.getAttributeValue(null, "format");
                                if (!"pem".equalsIgnoreCase(format)) {
                                    Log.w(TAG, "Unsupported Certificate format: " + format);
                                    return false;
                                }
                                if (currentAlg != null) {
                                    p.next();
                                    certCount++;
                                    keyboxData.put(currentAlg + ".CERT_" + certCount, p.getText().trim());
                                }
                                break;
                            }
                        }
                    }
                }

                if (!numberOfKeyboxesChecked) {
                    Log.w(TAG, "Missing <NumberOfKeyboxes> in keybox XML, continuing");
                }

                if (!hasKeybox()) {
                    Log.w(TAG, "Failed to load keybox from XML setting, parsed entries: " + keyboxData.keySet());
                    return false;
                }

                logLoadedSummary("XML setting", declaredKeyboxes);
                return true;
            } catch (Exception e) {
                Log.e(TAG, "XML keybox load failed", e);
                return false;
            }
        }

        private void loadFromConfigArray(Context ctx) {
            final String[] entries =
                    ctx.getResources().getStringArray(R.array.config_certifiedKeybox);
            if (entries.length == 0) {
                // No keybox shipped in the overlay; the user has not picked one either.
                return;
            }

            for (String entry : entries) {
                String[] parts = entry.split(":", 2);
                if (parts.length == 2) {
                    keyboxData.put(parts[0], parts[1]);
                }
            }

            if (!hasKeybox()) {
                Log.w(TAG, "Incomplete keybox provided by overlays");
            } else {
                logLoadedSummary("config array", entries.length);
            }
        }

        private int countCerts(String prefix) {
            int count = 0;
            while (keyboxData.containsKey(prefix + ".CERT_" + (count + 1))) {
                count++;
            }
            return count;
        }

        private void logLoadedSummary(String source, int declaredKeyboxes) {
            int ecCerts = countCerts("EC");
            int rsaCerts = countCerts("RSA");
            String summary = "source=" + source
                    + " declared=" + declaredKeyboxes
                    + " EC=" + (ecCerts == 0 ? "absent"
                            : ecCerts + " certs" + (keyboxData.containsKey("EC.PRIV")
                                    ? "/key" : "/no-key"))
                    + " RSA=" + (rsaCerts == 0 ? "absent"
                            : rsaCerts + " certs" + (keyboxData.containsKey("RSA.PRIV")
                                    ? "/key" : "/no-key"));
            if (!summary.equals(sLastSummary)) {
                sLastSummary = summary;
                Log.i(TAG, "Loaded keybox: " + summary);
            }
        }

        @Override
        public boolean hasKeybox() {
            // A keybox only has to cover one algorithm; most current ones ship EC only.
            final boolean hasEc = keyboxData.containsKey("EC.PRIV")
                    && keyboxData.containsKey("EC.CERT_1");
            final boolean hasRsa = keyboxData.containsKey("RSA.PRIV")
                    && keyboxData.containsKey("RSA.CERT_1");
            return hasEc || hasRsa;
        }

        @Override
        public String getEcPrivateKey() {
            return keyboxData.get("EC.PRIV");
        }

        @Override
        public String getRsaPrivateKey() {
            return keyboxData.get("RSA.PRIV");
        }

        @Override
        public String[] getEcCertificateChain() {
            return getCertificateChain("EC");
        }

        @Override
        public String[] getRsaCertificateChain() {
            return getCertificateChain("RSA");
        }

        private String[] getCertificateChain(String prefix) {
            // Keep the order the certificates appear in the keybox, it is the chain order.
            List<String> dataList = new ArrayList<>();
            for (int i = 1; ; i++) {
                String cert = keyboxData.get(prefix + ".CERT_" + i);
                if (cert == null) break;
                dataList.add(cert);
            }
            return dataList.toArray(new String[0]);
        }
    }
}
