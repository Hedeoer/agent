package cn.hedeoer.common.entity;

import cn.hedeoer.common.enmu.RuleType;

import java.util.HashMap;
import java.util.Map;

/**
 * 服务规则 - 允许特定服务的流量
 */
public class ServiceRule extends AbstractFirewallRule {
    private String service;  // 服务名称 (如 http, ssh)
    
    public ServiceRule() {
        this.type = RuleType.SERVICE;
    }
    
    public ServiceRule(String zone, String service, boolean permanent) {
        this.zone = zone;
        this.service = service;
        this.type = RuleType.SERVICE;
        this.permanent = permanent;
    }
    
    public String getService() {
        return service;
    }
    
    public void setService(String service) {
        this.service = service;
    }
    
    @Override
    public Map<String, Object> toDBusParams() {
        Map<String, Object> params = new HashMap<>();
        params.put("zone", zone);
        params.put("service", service);
        return params;
    }
}
