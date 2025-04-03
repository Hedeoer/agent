package cn.hedeoer.firewalld;

/**
 * 规则类型枚举
 */
public enum RuleType {
    SERVICE,
    PORT,
    FORWARD_PORT,
    MASQUERADE,
    ICMP_BLOCK,
    RICH_RULE,
    INTERFACE,
    SOURCE,
    DIRECT_RULE;
}
