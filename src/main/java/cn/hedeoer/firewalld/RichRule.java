package cn.hedeoer.firewalld;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.HashMap;
import java.util.Map;

/**
 * 富规则 - 复杂的自定义规则
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RichRule extends AbstractFirewallRule {
    private String rule;     // 富规则文本
    private int priority;    // 规则优先级

    
    @Override
    public Map<String, Object> toDBusParams() {
        Map<String, Object> params = new HashMap<>();
        params.put("zone", zone);
        params.put("rule", rule);
        params.put("priority", priority);
        return params;
    }
}
