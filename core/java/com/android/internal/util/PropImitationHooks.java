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
import java.util.Arrays;

public class PropImitationHooks {

    private static final String TAG = "PropImitationHooks";
    private static final boolean DEBUG = false;

    private static final String[] sCertifiedProps =
            Resources.getSystem().getStringArray(R.array.config_certifiedBuildProperties);

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
        try {
            dlog("Setting prop " + key + " to " + value.toString());
            final Field field;
            if (key.startsWith("VERSION.")) {
                field = Build.VERSION.class.getDeclaredField(
                        key.substring("VERSION.".length()));
            } else {
                field = Build.class.getDeclaredField(key);
            }
            field.setAccessible(true);
            final Class<?> type = field.getType();
            if (type == int.class) {
                field.setInt(null, Integer.parseInt(value.toString()));
            } else if (type == long.class) {
                field.setLong(null, Long.parseLong(value.toString()));
            } else {
                field.set(null, value.toString());
            }
            field.setAccessible(false);
        } catch (NoSuchFieldException | IllegalAccessException
                | NumberFormatException e) {
            // VERSION.* members are static final and cannot be written by reflection.
            dlog("Failed to set prop " + key + ": " + e);
        }
    }

    private static void setCertifiedPropsForGms() {
        if (sCertifiedProps.length == 0) {
            Log.e(TAG, "No certified build properties configured");
            return;
        }
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
                for (String entry : sCertifiedProps) {
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

    public static void onEngineGetCertificateChain() {
        // Attestation is spoofed by KeyboxImitationHooks; do not block it here or
        // Play Integrity never sees the spoofed chain.
        dlog("Key attestation requested, sIsGms=" + sIsGms + " sIsFinsky=" + sIsFinsky);
    }

    public static void dlog(String msg) {
        if (DEBUG) Log.d(TAG, "[" + sProcessName + "] " + msg);
    }
}
