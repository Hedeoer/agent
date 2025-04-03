package cn.hedeoer.firewalld;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.HashMap;
import java.util.Map;

/**
 * 源地址规则 - 基于源IP地址控制流量
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class SourceRule extends AbstractFirewallRule {
    private String source;  // 源IP地址或CIDR

    @Override
    public Map<String, Object> toDBusParams() {
        Map<String, Object> params = new HashMap<>();
        params.put("zone", zone);
        params.put("source", source);
        return params;
    }
}
