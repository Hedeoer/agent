package cn.hedeoer.common.enmu;

/**
 * 表示防火墙操作类型的枚举
 */
public enum FirewallOperationType {

    /**
     * 查询防火墙状态
     */
    QUERY("query"),
    /**
     * 启动操作
     */
    START("start"),
    
    /**
     * 停止操作
     */
    STOP("stop"),
    
    /**
     * 重启操作
     */
    RESTART("restart"),

    /**
     * 禁用ping
     */
    BLOCKPING("blockping"),

    /**
     * 启用用ping
     */
    UNBLOCKPING("unblockping");

    private final String value;
    
    /**
     * 构造函数
     * 
     * @param value 操作类型的字符串值
     */
    FirewallOperationType(String value) {
        this.value = value;
    }
    
    /**
     * 获取操作类型的字符串值
     * 
     * @return 操作类型的字符串表示
     */
    public String getValue() {
        return value;
    }
    
    /**
     * 根据字符串值获取对应的枚举实例
     * 
     * @param value 要查找的字符串值
     * @return 对应的枚举实例，如果未找到则返回null
     */
    public static FirewallOperationType fromValue(String value) {
        for (FirewallOperationType type : FirewallOperationType.values()) {
            if (type.value.equals(value)) {
                return type;
            }
        }
        return null;
    }
}