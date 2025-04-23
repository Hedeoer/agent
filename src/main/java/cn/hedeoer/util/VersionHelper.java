package cn.hedeoer.util;

import cn.hedeoer.Main;

public class VersionHelper {
    public static String getVersion() {
        Package pkg = Main.class.getPackage();
        if (pkg != null) {
            String v = pkg.getImplementationVersion();
            if (v != null) return v;
        }
        return "unknown";
    }
}
