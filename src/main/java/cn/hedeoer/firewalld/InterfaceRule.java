package cn.hedeoer.firewalld;

import java.util.HashMap;
import java.util.Map;

/**
 * 接口规则 - 将网络接口分配到特定区域
 */
public class InterfaceRule extends AbstractFirewallRule {
    private String interfaceName;  // 网络接口名称
    
    public InterfaceRule() {
        this.type = RuleType.INTERFACE;
    }
    
    public InterfaceRule(String zone, String interfaceName, boolean permanent) {
        this.zone = zone;
        this.interfaceName = interfaceName;
        this.type = RuleType.INTERFACE;
        this.permanent = permanent;
    }
    
    public String getInterfaceName() {
        return interfaceName;
    }
    
    public void setInterfaceName(String interfaceName) {
        this.interfaceName = interfaceName;
    }
    
    @Override
    public Map<String, Object> toDBusParams() {
        Map<String, Object> params = new HashMap<>();
        params.put("zone", zone);
        params.put("interface", interfaceName);
        return params;
    }
}
