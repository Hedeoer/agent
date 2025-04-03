package cn.hedeoer.firewalld;

import java.util.HashMap;
import java.util.Map;

/**
 * 端口规则 - 允许特定端口的流量
 */
public class PortRule extends AbstractFirewallRule {
    private String port;      // 端口号或范围 (如 "80" 或 "1024-2048")
    private String protocol;  // 协议 (tcp 或 udp)
    
    public PortRule() {
        this.type = RuleType.PORT;
    }
    
    public PortRule(String zone, String port, String protocol, boolean permanent) {
        this.zone = zone;
        this.port = port;
        this.protocol = protocol;
        this.type = RuleType.PORT;
        this.permanent = permanent;
    }
    
    public String getPort() {
        return port;
    }
    
    public void setPort(String port) {
        this.port = port;
    }
    
    public String getProtocol() {
        return protocol;
    }
    
    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }
    
    @Override
    public Map<String, Object> toDBusParams() {
        Map<String, Object> params = new HashMap<>();
        params.put("zone", zone);
        params.put("port", port);
        params.put("protocol", protocol);
        return params;
    }
}
