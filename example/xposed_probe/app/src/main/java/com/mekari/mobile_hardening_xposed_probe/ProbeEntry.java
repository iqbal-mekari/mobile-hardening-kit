package com.mekari.mobile_hardening_xposed_probe;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public final class ProbeEntry implements IXposedHookLoadPackage {
    private static final String TARGET_PACKAGE = "com.mekari.mobile_hardening_kit_example";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam packageParam) {
        if (TARGET_PACKAGE.equals(packageParam.packageName)) {
            XposedBridge.log("Mobile Hardening Xposed probe loaded in " + packageParam.packageName);
        }
    }
}
