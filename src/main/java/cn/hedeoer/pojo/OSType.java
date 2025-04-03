package cn.hedeoer.pojo;

import lombok.Data;

/**
 * 操作系统类型枚举
 * 只支持 linux
 */

public enum OSType {
    WINDOWS("WINDOWS", "Windows")
    , LINUX("LINUX", "Linux")
    , UNIX("UNIX", "Unix")
    , MAC("MAC", "Mac OS")
    , SOLARIS("SOLARIS", "Solaris OS")
    , UNKNOWN("UNKNOWN", "Unknown OS")
    ;

    private String code;
    private String name;

    OSType(String code, String name) {
        this.code = code;
        this.name = name;
    }

    public static String getName(String code) {
        for (OSType c : OSType.values()) {
            if (c.getCode().equals(code)) {
                return c.name();
            }
        }
        return null;
    }

    public static OSType getEnum(String code) {
        for (OSType c : OSType.values()) {
            if (c.getCode().equals(code)) {
                return c;
            }
        }
        return null;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
