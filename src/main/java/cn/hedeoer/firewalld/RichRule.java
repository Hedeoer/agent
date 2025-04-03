package cn.hedeoer.firewalld;

import java.util.HashMap;
import java.util.Map;

/**
 * 富规则 - 复杂的自定义规则
 */
public class RichRule extends AbstractFirewallRule {
    private String rule;     // 富规则文本
    private int priority;    // 规则优先级
    
    public RichRule() {
        this.type = RuleType.RICH_RULE;
    }
    
    public RichRule(String zone, String rule, int priority, boolean permanent) {
        this.zone = zone;
        this.rule = rule;
        this.priority = priority;
        this.type = RuleType.RICH_RULE;
        this.permanent = permanent;
    }
    
    public String getRule() {
        return rule;
    }
    
    public void setRule(String rule) {
        this.rule = rule;
    }
    
    public int getPriority() {
        return priority;
    }
    
    public void setPriority(int priority) {
        this.priority = priority;
    }
    
    @Override
    public Map<String, Object> toDBusParams() {
        Map<String, Object> params = new HashMap<>();
        params.put("zone", zone);
        params.put("rule", rule);
        params.put("priority", priority);
        return params;
    }
}
