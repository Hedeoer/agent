package cn.hedeoer.firewalld;

import java.util.HashMap;
import java.util.Map;

/**
 * 源地址规则 - 基于源IP地址控制流量
 */
public class SourceRule extends AbstractFirewallRule {
    private String source;  // 源IP地址或CIDR
    
    public SourceRule() {
        this.type = RuleType.SOURCE;
    }
    
    public SourceRule(String zone, String source, boolean permanent) {
        this.zone = zone;
        this.source = source;
        this.type = RuleType.SOURCE;
        this.permanent = permanent;
    }
    
    public String getSource() {
        return source;
    }
    
    public void setSource(String source) {
        this.source = source;
    }
    
    @Override
    public Map<String, Object> toDBusParams() {
        Map<String, Object> params = new HashMap<>();
        params.put("zone", zone);
        params.put("source", source);
        return params;
    }
}
