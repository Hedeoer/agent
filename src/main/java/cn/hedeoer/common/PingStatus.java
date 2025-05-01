package cn.hedeoer.common;

/**
 * 防火墙状态类型
 * STATUS_ENABLE 表示"禁用 ping 功能已启用"（即不允许被 ping）
 * STATUS_DISABLE 表示"禁用 ping 功能已禁用"（即允许被 ping）
 * STATUS_NONE 表示无法确定状态（配置文件不存在）
 */
public enum PingStatus {
    STATUS_NONE,
    STATUS_ENABLE,
    STATUS_DISABLE
}