package cn.hedeoer.firewalld;

import java.util.HashMap;
import java.util.Map;

/**
 * 地址伪装规则 - 启用NAT伪装
 */
public class MasqueradeRule extends AbstractFirewallRule {
    private boolean enabled;  // 是否启用伪装
    
    public MasqueradeRule() {
        this.type = RuleType.MASQUERADE;
    }
    
    public MasqueradeRule(String zone, boolean enabled, boolean permanent) {
        this.zone = zone;
        this.enabled = enabled;
        this.type = RuleType.MASQUERADE;
        this.permanent = permanent;
    }
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    @Override
    public Map<String, Object> toDBusParams() {
        Map<String, Object> params = new HashMap<>();
        params.put("zone", zone);
        params.put("enabled", enabled);
        return params;
    }
}
