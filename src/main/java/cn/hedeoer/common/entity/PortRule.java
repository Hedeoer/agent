package cn.hedeoer.common.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * 端口规则 - 允许特定端口的流量
 */
@Getter
@Setter
@ToString(callSuper = true)
@AllArgsConstructor
@NoArgsConstructor
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class PortRule extends AbstractFirewallRule {
    private String family;    // ip type (ipv4 ,ipv6,ipv4/ipv6)
    private String port;      // 端口号或范围 (如 "80" 或 "1024-2048")
    private String protocol;  // 协议 (tcp 或 udp)
    private Boolean using;    // 端口使用状态 （已使用，未使用）
    private Boolean policy;   // 端口策略（允许，拒绝）
    private SourceRule sourceRule; // 源IP地址或CIDR
    private String descriptor; //端口描述信息

    /**
     * 对象比较只包含 family, port、protocol sourceRule，policy 和父类属性（agentId，permanent，type，zone）
     * @param o
     * @return
     */
    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        PortRule portRule = (PortRule) o;
        return Objects.equals(family, portRule.family)
                &&  Objects.equals(port, portRule.port)
                && Objects.equals(protocol, portRule.protocol)
                && Objects.equals(sourceRule,portRule.sourceRule)
                && Objects.equals(policy,portRule.policy);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), family,port, protocol,sourceRule,policy);
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
