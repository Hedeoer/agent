package cn.hedeoer.common.entity;

import cn.hedeoer.common.enmu.RuleType;

import java.util.HashMap;
import java.util.Map;

/**
 * ICMP阻止规则 - 阻止特定ICMP类型
 */
public class IcmpBlockRule extends AbstractFirewallRule {
    private String icmpType;  // ICMP类型名称
    
    public IcmpBlockRule() {
        this.type = RuleType.ICMP_BLOCK;
    }
    
    public IcmpBlockRule(String zone, String icmpType, boolean permanent) {
        this.zone = zone;
        this.icmpType = icmpType;
        this.type = RuleType.ICMP_BLOCK;
        this.permanent = permanent;
    }
    
    public String getIcmpType() {
        return icmpType;
    }
    
    public void setIcmpType(String icmpType) {
        this.icmpType = icmpType;
    }
    
    @Override
    public Map<String, Object> toDBusParams() {
        Map<String, Object> params = new HashMap<>();
        params.put("zone", zone);
        params.put("icmptype", icmpType);
        return params;
    }
}
