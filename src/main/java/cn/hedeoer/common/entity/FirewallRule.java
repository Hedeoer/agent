package cn.hedeoer.common.entity;

import cn.hedeoer.common.enmu.RuleType;

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