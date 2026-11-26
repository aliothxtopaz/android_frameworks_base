/*
 * Copyright (C) 2020 The Pixel Experience Project
 *               2025 the AxionAOSP Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.internal.util.android;

import android.app.Application;
import android.content.Context;
import android.graphics.Rect;
import android.os.Build;
import android.os.SystemProperties;
import android.text.TextUtils;
import android.util.ArrayMap;
import android.util.ArraySet;
import android.util.DisplayMetrics;
import android.util.Log;
import android.view.WindowManager;

import java.lang.reflect.Field;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import java.util.Set;

public class PropsHooksUtils {

    private static final String TAG = PropsHooksUtils.class.getSimpleName();

    private static final String SPOOF_ALL = "persist.sys.pixelprops.all";
    private static final String SPOOF_PIXEL_GMS = "persist.sys.pixelprops.gms";
    private static final String SPOOF_PIXEL_GOOGLE = "persist.sys.pixelprops.google";
    private static final String SPOOF_PIXEL_GPHOTOS = "persist.sys.pixelprops.gphotos";
    private static final String SPOOF_GAMES = "persist.sys.gameprops.enable";
    private static final String PIHOOKS_PREFIX = "persist.sys.pihooks_";
    private static final String PER_APP_PREFIX = "persist.sys.per_app_props.";

    private static final String PACKAGE_GMS = "com.google.android.gms";
    private static final String PACKAGE_FINSKY = "com.android.vending";
    private static final String PACKAGE_PHOTOS = "com.google.android.apps.photos";
    private static final String PACKAGE_INTELLIGENCE = "com.google.android.settings.intelligence";

    private static final String[] PIHOOK_KEYS = {
            "BRAND", "DEVICE", "MANUFACTURER", "MODEL", "PRODUCT", "FINGERPRINT",
            "ID", "HARDWARE", "RELEASE", "SECURITY_PATCH", "DEVICE_INITIAL_SDK_INT",
            "SDK_INT", "TAGS", "TYPE"
    };

    private static volatile boolean sIsPhotos;

    private static final Map<String, Object> propsPixelXL = new ArrayMap<>();
    private static final Map<String, Object> propsBS4 = createMap("2SM-X706B", "blackshark");
    private static final Map<String, Object> propsMI11TP = createMap("2107113SI", "Xiaomi");
    private static final Map<String, Object> propsMI13P = createMap("2210132C", "Xiaomi");
    private static final Map<String, Object> propsOP8P = createMap("IN2020", "OnePlus");
    private static final Map<String, Object> propsOP9P = createMap("LE2101", "OnePlus");
    private static final Map<String, Object> propsF5 = createMap("23049PCD8G", "Xiaomi");
    private static final Map<String, Object> propsROG6 = createMap("ASUS_AI2201", "asus");
    private static final Map<String, Object> propsROG8P = createMap("ASUS_AI2401_A", "asus");
    private static final Map<String, Object> propsLenovoY700 = createMap("Lenovo TB-9707F", "Lenovo");
    private static final Map<String, Object> propsS24Ultra = createMap("SM-S928B", "samsung");
    private static final Map<String, Object> propsS9Tab = createMap("SM-X916B", "samsung");

    private static final Map<String, Map<String, Object>> packagePropsMap = new ArrayMap<>();
    private static final Map<String, Map<String, Map<String, Object>>> pubgPropsMap
            = new ArrayMap<>();
    private static final Set<String> pubgPackages = new ArraySet<>();
    private static final Set<String> packagesToSpoof = new ArraySet<>();

    private static final Set<String> featuresPixel = new ArraySet<>();
    private static final Set<String> featuresNexus = new ArraySet<>();

    static {
        featuresPixel.add("PIXEL_2017_PRELOAD");
        featuresPixel.add("PIXEL_2018_PRELOAD");
        featuresPixel.add("PIXEL_2019_MIDYEAR_PRELOAD");
        featuresPixel.add("PIXEL_2019_PRELOAD");
        featuresPixel.add("PIXEL_2020_EXPERIENCE");
        featuresPixel.add("PIXEL_2020_MIDYEAR_EXPERIENCE");
        featuresPixel.add("PIXEL_EXPERIENCE");

        featuresNexus.add("com.google.android.apps.photos.NEXUS_PRELOAD");
        featuresNexus.add("com.google.android.apps.photos.nexus_preload");
        featuresNexus.add("com.google.android.feature.PIXEL_EXPERIENCE");
        featuresNexus.add("com.google.android.feature.GOOGLE_BUILD");
        featuresNexus.add("com.google.android.feature.GOOGLE_EXPERIENCE");

        propsPixelXL.put("BRAND", "google");
        propsPixelXL.put("MANUFACTURER", "Google");
        propsPixelXL.put("DEVICE", "marlin");
        propsPixelXL.put("PRODUCT", "marlin");
        propsPixelXL.put("HARDWARE", "marlin");
        propsPixelXL.put("ID", "QP1A.191005.007.A3");
        propsPixelXL.put("MODEL", "Pixel XL");
        propsPixelXL.put("FINGERPRINT",
                "google/marlin/marlin:10/QP1A.191005.007.A3/5972272:user/release-keys");

        addToMap(Set.of("com.proximabeta.mf.uamo"), propsBS4);

        addToMap(Set.of(
                "com.levelinfinite.hotta.gp",
                "com.supercell.brawlstars",
                "com.supercell.clashofclans",
                "com.vng.mlbbvn"
        ), propsMI11TP);

        addToMap(Set.of("com.levelinfinite.sgameGlobal", "com.tencent.tmgp.sgame"), propsMI13P);

        addToMap(Set.of(
                "com.netease.lztgglobal",
                "com.riotgames.league.wildrift",
                "com.riotgames.league.wildrifttw",
                "com.riotgames.league.wildriftvn",
                "com.riotgames.league.teamfighttactics",
                "com.riotgames.league.teamfighttacticstw",
                "com.riotgames.league.teamfighttacticsvn"
        ), propsOP8P);

        addToMap(Set.of(
                "com.epicgames.fortnite",
                "com.epicgames.portal",
                "com.tencent.lolm"
        ), propsOP9P);

        addToMap(Set.of("com.dts.freefiremax", "com.dts.freefireth"), propsF5);

        addToMap(Set.of(
                "com.ea.gp.fifamobile",
                "com.gameloft.android.ANMP.GloftA9HM",
                "com.madfingergames.legends",
                "com.pearlabyss.blackdesertm",
                "com.pearlabyss.blackdesertm.gl"
        ), propsROG6);

        addToMap(Set.of("com.ea.gp.apexlegendsmobilefps", "com.mobile.legends"), propsROG8P);

        addToMap(Set.of(
                "com.activision.callofduty.shooter",
                "com.garena.game.codm",
                "com.tencent.tmgp.kr.codm",
                "com.vng.codmvn"
        ), propsLenovoY700);

        pubgPackages.addAll(Set.of(
                "com.pubg.imobile",
                "com.pubg.krmobile",
                "com.rekoo.pubgm",
                "com.tencent.ig",
                "com.tencent.tmgp.pubgmhd",
                "com.vng.pubgmobile"
        ));

        for (String pkg : pubgPackages) {
            Map<String, Map<String, Object>> props = new ArrayMap<>();
            props.put("phone", propsS24Ultra);
            props.put("tablet", propsS9Tab);
            pubgPropsMap.put(pkg, props);
        }

        packagesToSpoof.addAll(packagePropsMap.keySet());
        packagesToSpoof.add(PACKAGE_GMS);
        packagesToSpoof.add(PACKAGE_FINSKY);
        packagesToSpoof.add(PACKAGE_PHOTOS);
        packagesToSpoof.add(PACKAGE_INTELLIGENCE);
        packagesToSpoof.addAll(pubgPackages);
    }

    private static void addToMap(Set<String> packages, Map<String, Object> props) {
        for (String pkg : packages) packagePropsMap.put(pkg, props);
    }

    private static Map<String, Object> createMap(String model, String manufacturer) {
        Map<String, Object> map = new ArrayMap<>();
        map.put("MODEL", model);
        map.put("MANUFACTURER", manufacturer);
        return map;
    }

    public static void setProps(Context context) {
        if (context == null) return;

        String packageName = context.getPackageName();
        if (TextUtils.isEmpty(packageName)) return;
        if (!packagesToSpoof.contains(packageName)
                && TextUtils.isEmpty(
                        SystemProperties.get(PER_APP_PREFIX + packageName + ".MODEL", null))) {
            return;
        }

        final String processName = Application.getProcessName();
        if (TextUtils.isEmpty(processName)) return;

        if (pubgPropsMap.containsKey(packageName)) {
            Map<String, Object> propsToApply = isLargeScreen(context)
                    ? pubgPropsMap.get(packageName).get("tablet")
                    : pubgPropsMap.get(packageName).get("phone");
            if (propsToApply != null) packagePropsMap.put(packageName, propsToApply);
        }

        if (shouldSpoofGames()) {
            Map<String, Object> props = packagePropsMap.get(packageName);
            if (props != null) {
                for (Map.Entry<String, Object> prop : props.entrySet()) {
                    setPropValue(packageName, prop.getKey(), prop.getValue());
                }
            }
        }

        applyPerAppProps(packageName);

        sIsPhotos = packageName.equals(PACKAGE_PHOTOS);
        if (shouldSpoofPhotos()) {
            for (Map.Entry<String, Object> entry : propsPixelXL.entrySet()) {
                setPropValue(packageName, entry.getKey(), entry.getValue());
            }
        }

        if (packageName.equals(PACKAGE_INTELLIGENCE)) {
            setPropValue(packageName, "FINGERPRINT", "eng.nobody." +
                    new SimpleDateFormat("yyyyMMdd.HHmmss").format(new Date()));
        }

        if (shouldSpoofGMS(packageName, processName)) {
            spoofBuildGms(packageName);
        }
    }

    /** Applies props written by the per-app spoofing JSON loader in Settings. */
    private static void applyPerAppProps(String packageName) {
        String prefix = PER_APP_PREFIX + packageName + ".";
        for (String key : PIHOOK_KEYS) {
            String value = SystemProperties.get(prefix + key, null);
            if (!TextUtils.isEmpty(value)) {
                setPropValue(packageName, key, value);
            }
        }
    }

    private static void setPropValue(String packageName, String key, Object newValue) {
        try {
            Field field = getBuildClassField(key);
            if (field == null) return;

            if (field.getType() == int.class) {
                field.setInt(null, newValue instanceof Integer
                        ? (Integer) newValue : Integer.parseInt(newValue.toString()));
            } else if (field.getType() == long.class) {
                field.setLong(null, newValue instanceof Long
                        ? (Long) newValue : Long.parseLong(newValue.toString()));
            } else {
                field.set(null, newValue.toString());
            }
        } catch (IllegalAccessException | IllegalArgumentException e) {
            Log.e(TAG, "Failed to set prop " + key + " for package " + packageName, e);
        }
    }

    private static Field getBuildClassField(String key) {
        try {
            Field field = Build.class.getDeclaredField(key);
            field.setAccessible(true);
            return field;
        } catch (NoSuchFieldException e1) {
            try {
                Field field = Build.VERSION.class.getDeclaredField(key);
                field.setAccessible(true);
                return field;
            } catch (NoSuchFieldException e2) {
                Log.e(TAG, "Field " + key + " not found", e2);
                return null;
            }
        }
    }

    private static boolean isSpoofingEnabled() {
        return SystemProperties.getBoolean(SPOOF_ALL, true);
    }

    private static boolean shouldSpoofGames() {
        return isSpoofingEnabled() && SystemProperties.getBoolean(SPOOF_GAMES, false);
    }

    private static boolean shouldSpoofPhotos() {
        return isSpoofingEnabled() && sIsPhotos
                && SystemProperties.getBoolean(SPOOF_PIXEL_GPHOTOS, true);
    }

    private static boolean shouldSpoofGMS(String packageName, String processName) {
        final boolean sIsGms = packageName.equals(PACKAGE_GMS)
                && processName.toLowerCase().contains("unstable");
        final boolean sIsFinsky = packageName.equals(PACKAGE_FINSKY);
        final boolean googleApps = SystemProperties.getBoolean(SPOOF_PIXEL_GOOGLE, true)
                && packageName.startsWith("com.google.");
        return isSpoofingEnabled() && (sIsGms || sIsFinsky || googleApps)
                && SystemProperties.getBoolean(SPOOF_PIXEL_GMS, true);
    }

    private static void spoofBuildGms(String pkg) {
        try {
            for (String key : PIHOOK_KEYS) {
                String value = SystemProperties.get(PIHOOKS_PREFIX + key, null);
                if (!TextUtils.isEmpty(value)) {
                    setPropValue(pkg, key, value);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to spoof Build props for " + pkg, e);
        }
    }

    public static boolean hasSystemFeature(String name, int version, boolean hasSystemFeature) {
        if (shouldSpoofPhotos()) {
            if (!isPixelDevice() && featuresPixel.contains(name)) return false;
            return featuresNexus.contains(name);
        }
        return hasSystemFeature;
    }

    private static boolean isPixelDevice() {
        return SystemProperties.get("ro.soc.manufacturer", "").equalsIgnoreCase("google");
    }

    private static boolean isLargeScreen(Context context) {
        try {
            WindowManager windowManager = context.getSystemService(WindowManager.class);
            if (windowManager == null) return false;
            final Rect bounds = windowManager.getMaximumWindowMetrics().getBounds();
            float smallestWidth = dpiFromPx(Math.min(bounds.width(), bounds.height()),
                    context.getResources().getConfiguration().densityDpi);
            return smallestWidth >= 600;
        } catch (Exception e) {
            // Child/sandboxed zygotes have no WindowManager yet.
            return false;
        }
    }

    private static float dpiFromPx(float size, int densityDpi) {
        return size / ((float) densityDpi / DisplayMetrics.DENSITY_DEFAULT);
    }
}