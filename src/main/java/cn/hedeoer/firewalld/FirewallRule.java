package cn.hedeoer.firewalld;

import java.util.Map;

/**
 * 所有防火墙规则的基础接口
 */
public interface FirewallRule {
    String getZone();
    RuleType getType();
    boolean isPermanent();
    Map<String, Object> toDBusParams();
}