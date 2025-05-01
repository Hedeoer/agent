package cn.hedeoer.common;

import java.util.Arrays;
import java.util.List;

/**
 * 防火墙状态枚举
 */
public enum FireWallStatus {
    /**
     * 防火墙处于活动状态
     */
    ACTIVE("active", "enabled"),
    
    /**
     * 防火墙处于非活动状态
     */
    INACTIVE("inactive", "disabled"),
    
    /**
     * 防火墙未安装
     */
    NOT_INSTALLED("not installed"),
    
    /**
     * 防火墙状态未知
     */
    UNKNOWN("unknown");
    
    private final List<String> statusTexts;
    
    FireWallStatus(String... statusTexts) {
        this.statusTexts = Arrays.asList(statusTexts);
    }
    
    /**
     * 根据状态文本获取对应的枚举值
     * 
     * @param statusText 状态文本
     * @return 对应的枚举值，如果没有匹配项则返回 UNKNOWN
     */
    public static FireWallStatus fromString(String statusText) {
        if (statusText == null) return UNKNOWN;
        
        String normalizedStatus = statusText.toLowerCase().trim();
        
        for (FireWallStatus status : values()) {
            if (status.statusTexts.contains(normalizedStatus)) {
                return status;
            }
        }
        
        return UNKNOWN;
    }
    
    /**
     * 获取状态的主要文本表示
     */
    public String getText() {
        return statusTexts.isEmpty() ? name().toLowerCase() : statusTexts.get(0);
    }
}