package cn.hedeoer.firewalld;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.HashMap;
import java.util.Map;

/**
 * 端口规则 - 允许特定端口的流量
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class PortRule extends AbstractFirewallRule {
    private String port;      // 端口号或范围 (如 "80" 或 "1024-2048")
    private String protocol;  // 协议 (tcp 或 udp)
    private Boolean using;    // 端口使用状态 （已使用，未使用）
    private Boolean policy;   // 端口策略（允许，拒绝）
    private SourceRule sourceRule; // 源IP地址或CIDR
    private String descriptor; //端口描述信息

    
    @Override
    public Map<String, Object> toDBusParams() {
        Map<String, Object> params = new HashMap<>();
        params.put("zone", zone);
        params.put("port", port);
        params.put("protocol", protocol);
        return params;
    }
}
