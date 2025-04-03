package cn.hedeoer.firewalld;

import java.util.HashMap;
import java.util.Map;

/**
 * 端口转发规则 - 将流量从一个端口转发到另一个端口/地址
 */
public class ForwardPortRule extends AbstractFirewallRule {
    private String port;           // 原始端口
    private String protocol;       // 协议 (tcp 或 udp)
    private String toPort;         // 目标端口
    private String toAddr;         // 目标地址 (可选)
    
    public ForwardPortRule() {
        this.type = RuleType.FORWARD_PORT;
    }
    
    // 构造函数
    public ForwardPortRule(String zone, String port, String protocol, 
                          String toPort, String toAddr, boolean permanent) {
        this.zone = zone;
        this.port = port;
        this.protocol = protocol;
        this.toPort = toPort;
        this.toAddr = toAddr;
        this.type = RuleType.FORWARD_PORT;
        this.permanent = permanent;
    }
    
    // Getters 和 Setters
    public String getPort() { return port; }
    public void setPort(String port) { this.port = port; }
    public String getProtocol() { return protocol; }
    public void setProtocol(String protocol) { this.protocol = protocol; }
    public String getToPort() { return toPort; }
    public void setToPort(String toPort) { this.toPort = toPort; }
    public String getToAddr() { return toAddr; }
    public void setToAddr(String toAddr) { this.toAddr = toAddr; }
    
    @Override
    public Map<String, Object> toDBusParams() {
        Map<String, Object> params = new HashMap<>();
        params.put("zone", zone);
        params.put("port", port);
        params.put("protocol", protocol);
        params.put("toport", toPort);
        if (toAddr != null && !toAddr.isEmpty()) {
            params.put("toaddr", toAddr);
        }
        return params;
    }
}
