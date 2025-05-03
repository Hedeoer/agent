package cn.hedeoer.common.entity;

import lombok.Data;

import java.util.HashMap;
import java.util.Map;

/**
 * 直接规则 - 直接传递到iptables/nftables的规则
 */
@Data
public class DirectRule extends AbstractFirewallRule {
    private String ipv;       // ipv4 或 ipv6
    private String table;     // 表名
    private String chain;     // 链名
    private int priority;     // 优先级
    private String command;   // 命令
    

    
    // 构造函数、getter和setter
    
    @Override
    public Map<String, Object> toDBusParams() {
        Map<String, Object> params = new HashMap<>();
        params.put("ipv", ipv);
        params.put("table", table);
        params.put("chain", chain);
        params.put("priority", priority);
        params.put("command", command);
        return params;
    }
}
