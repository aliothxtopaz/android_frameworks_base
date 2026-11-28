/*
 * Copyright (C) 2022 Paranoid Android
 *           (C) 2023 ArrowOS
 *           (C) 2023 The LibreMobileOS Foundation
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

package com.android.internal.util;

import android.app.ActivityTaskManager;
import android.app.Application;
import android.app.TaskStackListener;
import android.content.ComponentName;
import android.content.Context;
import android.content.res.Resources;
import android.os.Build;
import android.os.Binder;
import android.os.Process;
import android.os.SystemProperties;
import android.text.TextUtils;
import android.util.Log;

import com.android.internal.R;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.Objects;

public class PropImitationHooks {

    private static final String TAG = "PropImitationHooks";
    private static final boolean DEBUG = false;

    private static final String[] sCertifiedProps =
            Resources.getSystem().getStringArray(R.array.config_certifiedBuildProperties);

    // Used when the overlay-provided array is empty (Resources.getSystem() does not
    // always see RROs). A PIF JSON picked in Settings still overrides this.
    private static final String[] FALLBACK_CERTIFIED_PROPS = {
            "MANUFACTURER:Google",
            "BRAND:google",
            "DEVICE:caiman",
            "PRODUCT:caiman_beta",
            "MODEL:Pixel 9 Pro",
            "FINGERPRINT:google/caiman_beta/caiman:16/BP41.250916.009.A1/14246511:user/release-keys",
            "ID:BP41.250916.009.A1",
            "TAGS:release-keys",
            "TYPE:user",
            "SECURITY_PATCH:2025-10-05",
            "RELEASE:16",
            "DEVICE_INITIAL_SDK_INT:32",
    };

    private static final String sStockFp =
            Resources.getSystem().getString(R.string.config_stockFingerprint);

    private static final String sNetflixModel =
            Resources.getSystem().getString(R.string.config_netflixSpoofModel);

    private static final String ANDROIDX_TEST = "androidx.test";
    private static final String PACKAGE_ARCORE = "com.google.ar.core";
    private static final String PACKAGE_FINSKY = "com.android.vending";
    private static final String PACKAGE_GMS_RESTORE = "com.google.android.apps.restore";
    private static final String PACKAGE_GMS = "com.google.android.gms";
    private static final String PROCESS_GMS_UNSTABLE = "unstable";
    private static final String PROCESS_GMS_PERSISTENT = "persistent";
    private static final String PROCESS_GMS_PIXEL_MIGRATE = "pixelmigrate";
    private static final String PROCESS_INSTRUMENTATION = "instrumentation";
    private static final String PACKAGE_NETFLIX = "com.netflix.mediaclient";

    private static final ComponentName GMS_ADD_ACCOUNT_ACTIVITY = ComponentName.unflattenFromString(
            "com.google.android.gms/.auth.uiflows.minutemaid.MinuteMaidActivity");

    private static volatile String sProcessName;
    private static volatile boolean sIsGms, sIsFinsky, sIsPhotos;

    public static void setProps(Context context) {
        final String packageName = context.getPackageName();
        final String processName = Application.getProcessName();

        if (TextUtils.isEmpty(packageName) || TextUtils.isEmpty(processName)) {
            Log.e(TAG, "Null package or process name");
            return;
        }

        sProcessName = processName;
        final boolean isPackageGms = packageName.toLowerCase().contains(ANDROIDX_TEST)
                || packageName.equals(PACKAGE_GMS_RESTORE)
                || packageName.equals(PACKAGE_GMS);
        sIsGms = isPackageGms && (processName.toLowerCase().contains(PROCESS_GMS_UNSTABLE)
                || processName.toLowerCase().contains(PROCESS_GMS_PERSISTENT)
                || processName.toLowerCase().contains(PROCESS_GMS_PIXEL_MIGRATE)
                || processName.toLowerCase().contains(PROCESS_INSTRUMENTATION));
        sIsFinsky = packageName.equals(PACKAGE_FINSKY);

        /* Set Certified Properties for GMSCore
         * Set Stock Fingerprint for ARCore
         * Set custom model for Netflix
         */
        if (sIsGms) {
            setCertifiedPropsForGms();
        } else if (!sStockFp.isEmpty() && packageName.equals(PACKAGE_ARCORE)) {
            dlog("Setting stock fingerprint for: " + packageName);
            setPropValue("FINGERPRINT", sStockFp);
        } else if (!sNetflixModel.isEmpty() && packageName.equals(PACKAGE_NETFLIX)) {
            dlog("Setting model to " + sNetflixModel + " for Netflix");
            setPropValue("MODEL", sNetflixModel);
        }
    }

    private static void setPropValue(String key, Object value) {
        setBuildField(key, value);
    }

    /**
     * Writes a Build/Build.VERSION field, using Unsafe for static finals and
     * reading the value back. Shared with PropsHooksUtils so PIF JSON values
     * hit the same path.
     */
    public static void setBuildField(String key, Object value) {
        try {
            Field field = findBuildField(key);
            if (field == null) {
                dlog("No Build field for " + key);
                return;
            }

            Object newValue = value;
            Class<?> type = field.getType();
            if (type == int.class) {
                newValue = value instanceof Integer
                        ? value : Integer.parseInt(value.toString());
            } else if (type == long.class) {
                newValue = value instanceof Long
                        ? value : Long.parseLong(value.toString());
            } else if (type == boolean.class) {
                newValue = value instanceof Boolean
                        ? value : Boolean.parseBoolean(value.toString());
            } else if (type == String.class) {
                newValue = value.toString();
            } else {
                dlog("Unsupported Build field type " + type + " for " + key);
                return;
            }

            Object oldValue = field.get(null);
            setStaticField(field, newValue);
            dlog("Setting prop " + key + ": " + oldValue + " -> " + newValue);
        } catch (Exception e) {
            Log.e(TAG, "Failed to set prop " + key, e);
        }
    }

    private static Field findBuildField(String key) {
        if (key.startsWith("VERSION.")) {
            try {
                return Build.VERSION.class.getDeclaredField(
                        key.substring("VERSION.".length()));
            } catch (NoSuchFieldException e) {
                return null;
            }
        }
        try {
            return Build.class.getDeclaredField(key);
        } catch (NoSuchFieldException e) {
            // RELEASE, SECURITY_PATCH and SDK_INT live in Build.VERSION.
            try {
                return Build.VERSION.class.getDeclaredField(key);
            } catch (NoSuchFieldException ignored) {
                return null;
            }
        }
    }

    /**
     * Writes a static field, falling back to Unsafe when ART refuses to set a
     * static final one (Build.VERSION.RELEASE, SECURITY_PATCH, SDK_INT). The
     * write is read back so a silent no-op is reported instead of looking like
     * a successful spoof.
     *
     * Adapted from Lunaris-AOSP frameworks_base (16.2) PlayIntegritySpoofService.
     */
    private static void setStaticField(Field field, Object value) throws Exception {
        field.setAccessible(true);
        try {
            try {
                field.set(null, value);
            } catch (Exception e) {
                putStaticViaUnsafe(field, value);
            }
            Object now = field.get(null);
            if (!Objects.equals(now, value)) {
                putStaticViaUnsafe(field, value);
                now = field.get(null);
                if (!Objects.equals(now, value)) {
                    throw new IllegalStateException("write to " + field.getName()
                            + " did not stick (still " + now + ")");
                }
            }
        } finally {
            field.setAccessible(false);
        }
    }

    private static final Object sUnsafeLock = new Object();
    private static boolean sUnsafeLookedUp;
    private static Object sUnsafe;
    private static Method sPutObject;
    private static Method sPutInt;
    private static Method sPutLong;
    private static Method sPutBoolean;
    private static Field sFieldOffset;
    private static Method sFieldGetOffset;

    private static boolean initUnsafe() {
        synchronized (sUnsafeLock) {
            if (sUnsafeLookedUp) {
                return sUnsafe != null && sPutObject != null
                        && (sFieldOffset != null || sFieldGetOffset != null);
            }
            sUnsafeLookedUp = true;

            try {
                Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
                Object unsafe = null;
                for (String name : new String[] { "theUnsafe", "THE_ONE" }) {
                    try {
                        Field f = unsafeClass.getDeclaredField(name);
                        f.setAccessible(true);
                        unsafe = f.get(null);
                        if (unsafe != null) break;
                    } catch (Throwable ignored) {
                    }
                }
                if (unsafe == null) {
                    try {
                        unsafe = unsafeClass.getMethod("getUnsafe").invoke(null);
                    } catch (Throwable ignored) {
                    }
                }
                if (unsafe == null) {
                    Log.w(TAG, "sun.misc.Unsafe instance unavailable");
                    return false;
                }

                sPutObject = unsafeClass.getMethod("putObject",
                        Object.class, long.class, Object.class);
                sPutInt = unsafeClass.getMethod("putInt",
                        Object.class, long.class, int.class);
                sPutLong = unsafeClass.getMethod("putLong",
                        Object.class, long.class, long.class);
                try {
                    sPutBoolean = unsafeClass.getMethod("putBoolean",
                            Object.class, long.class, boolean.class);
                } catch (NoSuchMethodException ignored) {
                }
                sUnsafe = unsafe;
            } catch (Throwable t) {
                Log.w(TAG, "Failed to resolve sun.misc.Unsafe: " + t);
                sUnsafe = null;
                return false;
            }

            try {
                Field f = Field.class.getDeclaredField("offset");
                f.setAccessible(true);
                sFieldOffset = f;
            } catch (Throwable ignored) {
            }
            if (sFieldOffset == null) {
                try {
                    Method m = Field.class.getDeclaredMethod("getOffset");
                    m.setAccessible(true);
                    sFieldGetOffset = m;
                } catch (Throwable ignored) {
                }
            }
            if (sFieldOffset == null && sFieldGetOffset == null) {
                Log.w(TAG, "Unable to resolve java.lang.reflect.Field offset");
                return false;
            }
            return true;
        }
    }

    private static long fieldOffset(Field field) throws ReflectiveOperationException {
        if (sFieldOffset != null) {
            return ((Number) sFieldOffset.get(field)).longValue();
        }
        return ((Number) sFieldGetOffset.invoke(field)).longValue();
    }

    private static void putStaticViaUnsafe(Field field, Object value)
            throws ReflectiveOperationException {
        if (!initUnsafe()) {
            throw new IllegalStateException("Unsafe fallback unavailable");
        }
        if (!Modifier.isStatic(field.getModifiers())) {
            throw new IllegalArgumentException(field.getName() + " is not static");
        }

        Object base = field.getDeclaringClass();
        long offset = fieldOffset(field);
        Class<?> type = field.getType();

        if (!type.isPrimitive()) {
            sPutObject.invoke(sUnsafe, base, offset, value);
        } else if (type == int.class) {
            sPutInt.invoke(sUnsafe, base, offset, ((Number) value).intValue());
        } else if (type == long.class) {
            sPutLong.invoke(sUnsafe, base, offset, ((Number) value).longValue());
        } else if (type == boolean.class && sPutBoolean != null) {
            sPutBoolean.invoke(sUnsafe, base, offset, (Boolean) value);
        } else {
            throw new IllegalArgumentException("Unsupported static type " + type);
        }
    }

    private static void setCertifiedPropsForGms() {
        final String[] certifiedProps = sCertifiedProps.length == 0
                ? FALLBACK_CERTIFIED_PROPS : sCertifiedProps;
        final boolean was = isGmsAddAccountActivityOnTop();
        final TaskStackListener taskStackListener = new TaskStackListener() {
            @Override
            public void onTaskStackChanged() {
                final boolean is = isGmsAddAccountActivityOnTop();
                if (is ^ was) {
                    dlog("GmsAddAccountActivityOnTop is:" + is + " was:" + was +
                            ", killing myself!"); // process will restart automatically later
                    Process.killProcess(Process.myPid());
                }
            }
        };
        if (!was) {
            // A PIF JSON picked in Settings takes precedence over the built-in list.
            if (!SystemProperties.get("persist.sys.pihooks_FINGERPRINT", "").isEmpty()) {
                dlog("User PIF applied, skipping certified props");
            } else {
                dlog("Spoofing build for GMS");
                for (String entry : certifiedProps) {
                    final int split = entry.indexOf(':');
                    if (split <= 0 || split == entry.length() - 1) continue;
                    setPropValue(entry.substring(0, split).trim(),
                            entry.substring(split + 1).trim());
                }
                Log.i(TAG, "Spoofed GMS build: " + Build.FINGERPRINT
                        + " model=" + Build.MODEL);
            }
        } else {
            dlog("Skip spoofing build for GMS, because GmsAddAccountActivityOnTop");
        }
        try {
            ActivityTaskManager.getService().registerTaskStackListener(taskStackListener);
        } catch (Exception e) {
            Log.e(TAG, "Failed to register task stack listener!", e);
        }
    }

    private static boolean isGmsAddAccountActivityOnTop() {
        try {
            final ActivityTaskManager.RootTaskInfo focusedTask =
                    ActivityTaskManager.getService().getFocusedRootTaskInfo();
            return focusedTask != null && focusedTask.topActivity != null
                    && focusedTask.topActivity.equals(GMS_ADD_ACCOUNT_ACTIVITY);
        } catch (Exception e) {
            Log.e(TAG, "Unable to get top activity!", e);
        }
        return false;
    }

    public static boolean shouldBypassTaskPermission(Context context) {
        // GMS doesn't have MANAGE_ACTIVITY_TASKS permission
        final int callingUid = Binder.getCallingUid();
        final int gmsUid;
        try {
            gmsUid = context.getPackageManager().getApplicationInfo(PACKAGE_GMS, 0).uid;
            dlog("shouldBypassTaskPermission: gmsUid:" + gmsUid + " callingUid:" + callingUid);
        } catch (Exception e) {
            Log.e(TAG, "shouldBypassTaskPermission: unable to get gms uid", e);
            return false;
        }
        return gmsUid == callingUid;
    }

    private static boolean isCallerSafetyNet() {
        return sIsGms && Arrays.stream(Thread.currentThread().getStackTrace())
                .anyMatch(elem -> elem.getClassName().contains("DroidGuard"));
    }

    public static boolean isSpoofingGms() {
        return sIsGms || sIsFinsky;
    }

    public static void onEngineGetCertificateChain() {
        // Attestation is spoofed by KeyboxImitationHooks; do not block it here or
        // Play Integrity never sees the spoofed chain.
        dlog("Key attestation requested, sIsGms=" + sIsGms + " sIsFinsky=" + sIsFinsky);
    }

    public static void dlog(String msg) {
        if (DEBUG) Log.d(TAG, "[" + sProcessName + "] " + msg);
    }
}
