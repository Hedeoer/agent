package cn.hedeoer.firewall.firewalld;

import cn.hedeoer.common.enmu.RuleType;
import cn.hedeoer.common.entity.*;

import java.util.Map;
import java.util.List;
import java.util.HashMap;

/**
 * 防火墙规则工厂类 - 负责从D-Bus数据创建各种规则对象
 */
public class FirewallRuleFactory {
    
    /**
     * 从D-Bus返回的数据创建适当的规则对象
     * @param data D-Bus返回的数据
     * @param type 规则类型
     * @param permanent 是否为永久规则
     * @return 对应类型的FirewallRule对象
     */
    public static FirewallRule createFromDBusData(Map<String, Object> data, RuleType type, boolean permanent) {
        switch (type) {
            case SERVICE:
                return createServiceRule(data, permanent);
            case PORT:
                return createPortRule(data, permanent);
            case FORWARD_PORT:
                return createForwardPortRule(data, permanent);
            case MASQUERADE:
                return createMasqueradeRule(data, permanent);
            case ICMP_BLOCK:
                return createIcmpBlockRule(data, permanent);
            case RICH_RULE:
                return createRichRule(data, permanent);
            case INTERFACE:
                return createInterfaceRule(data, permanent);
            case SOURCE:
                return createSourceRule(data, permanent);
            case DIRECT_RULE:
                return createDirectRule(data, permanent);
            default:
                throw new IllegalArgumentException("Unsupported rule type: " + type);
        }
    }
    
    /**
     * 从字符串列表创建规则对象
     * 适用于D-Bus接口返回多条规则的情况
     * @param zone 区域名称
     * @param dataList 规则数据列表
     * @param type 规则类型
     * @param permanent 是否永久规则
     * @return 规则对象列表
     */
    public static List<FirewallRule> createRulesFromStringList(String zone, List<String> dataList, 
                                                              RuleType type, boolean permanent) {
        List<FirewallRule> rules = new java.util.ArrayList<>();
        
        for (String data : dataList) {
            Map<String, Object> ruleData = new HashMap<>();
            ruleData.put("zone", zone);
            
            switch (type) {
                case SERVICE:
                    ruleData.put("service", data);
                    rules.add(createServiceRule(ruleData, permanent));
                    break;
                case PORT:
                    // 端口格式通常为 "port/protocol"
                    String[] parts = data.split("/");
                    if (parts.length == 2) {
                        ruleData.put("port", parts[0]);
                        ruleData.put("protocol", parts[1]);
                        rules.add(createPortRule(ruleData, permanent));
                    }
                    break;
                case RICH_RULE:
                    ruleData.put("rule", data);
                    rules.add(createRichRule(ruleData, permanent));
                    break;
                // 其他类型处理...
            }
        }
        
        return rules;
    }
    
    /**
     * 创建服务规则
     */
    private static ServiceRule createServiceRule(Map<String, Object> data, boolean permanent) {
        ServiceRule rule = new ServiceRule();
        rule.setZone(getStringValue(data, "zone"));
        rule.setService(getStringValue(data, "service"));
        rule.setPermanent(permanent);
        return rule;
    }
    
    /**
     * 创建端口规则
     */
    private static PortRule createPortRule(Map<String, Object> data, boolean permanent) {
        PortRule rule = new PortRule();
        rule.setZone(getStringValue(data, "zone"));
        rule.setPort(getStringValue(data, "port"));
        rule.setProtocol(getStringValue(data, "protocol"));
        rule.setPermanent(permanent);
        return rule;
    }
    
    /**
     * 创建端口转发规则
     */
    private static ForwardPortRule createForwardPortRule(Map<String, Object> data, boolean permanent) {
        ForwardPortRule rule = new ForwardPortRule();
        rule.setZone(getStringValue(data, "zone"));
        rule.setPort(getStringValue(data, "port"));
        rule.setProtocol(getStringValue(data, "protocol"));
        rule.setToPort(getStringValue(data, "toport"));
        rule.setToAddr(getStringValue(data, "toaddr"));
        rule.setPermanent(permanent);
        return rule;
    }
    
    /**
     * 创建地址伪装规则
     */
    private static MasqueradeRule createMasqueradeRule(Map<String, Object> data, boolean permanent) {
        MasqueradeRule rule = new MasqueradeRule();
        rule.setZone(getStringValue(data, "zone"));
        
        // D-Bus可能返回布尔值或字符串
        Object enabled = data.get("enabled");
        if (enabled instanceof Boolean) {
            rule.setEnabled((Boolean) enabled);
        } else if (enabled instanceof String) {
            rule.setEnabled(Boolean.parseBoolean((String) enabled));
        } else {
            // 默认假设启用
            rule.setEnabled(true);
        }
        
        rule.setPermanent(permanent);
        return rule;
    }
    
    /**
     * 创建ICMP阻止规则
     */
    private static IcmpBlockRule createIcmpBlockRule(Map<String, Object> data, boolean permanent) {
        IcmpBlockRule rule = new IcmpBlockRule();
        rule.setZone(getStringValue(data, "zone"));
        rule.setIcmpType(getStringValue(data, "icmptype"));
        rule.setPermanent(permanent);
        return rule;
    }
    
    /**
     * 创建富规则
     */
    private static RichRule createRichRule(Map<String, Object> data, boolean permanent) {
        RichRule rule = new RichRule();
        rule.setZone(getStringValue(data, "zone"));
        rule.setRule(getStringValue(data, "rule"));
        
        // 优先级可能有或没有
        Object priority = data.get("priority");
        if (priority != null) {
            if (priority instanceof Integer) {
                rule.setPriority((Integer) priority);
            } else if (priority instanceof String) {
                try {
                    rule.setPriority(Integer.parseInt((String) priority));
                } catch (NumberFormatException e) {
                    rule.setPriority(0);  // 默认优先级
                }
            }
        } else {
            rule.setPriority(0);  // 默认优先级
        }
        
        rule.setPermanent(permanent);
        return rule;
    }
    
    /**
     * 创建接口规则
     */
    private static InterfaceRule createInterfaceRule(Map<String, Object> data, boolean permanent) {
        InterfaceRule rule = new InterfaceRule();
        rule.setZone(getStringValue(data, "zone"));
        rule.setInterfaceName(getStringValue(data, "interface"));
        rule.setPermanent(permanent);
        return rule;
    }
    
    /**
     * 创建源地址规则
     */
    private static SourceRule createSourceRule(Map<String, Object> data, boolean permanent) {
        SourceRule rule = new SourceRule();
        rule.setZone(getStringValue(data, "zone"));
        rule.setSource(getStringValue(data, "source"));
        rule.setPermanent(permanent);
        return rule;
    }
    
    /**
     * 创建直接规则
     */
    private static DirectRule createDirectRule(Map<String, Object> data, boolean permanent) {
        DirectRule rule = new DirectRule();
        rule.setZone(getStringValue(data, "zone", ""));  // 直接规则可能没有区域
        rule.setIpv(getStringValue(data, "ipv"));
        rule.setTable(getStringValue(data, "table"));
        rule.setChain(getStringValue(data, "chain"));
        
        // 处理优先级
        Object priority = data.get("priority");
        if (priority instanceof Integer) {
            rule.setPriority((Integer) priority);
        } else if (priority instanceof String) {
            try {
                rule.setPriority(Integer.parseInt((String) priority));
            } catch (NumberFormatException e) {
                rule.setPriority(0);
            }
        } else {
            rule.setPriority(0);
        }
        
        // 处理命令，可能是字符串或字符串数组
        Object command = data.get("command");
        if (command instanceof String) {
            rule.setCommand((String) command);
        } else if (command instanceof String[]) {
            rule.setCommand(String.join(" ", (String[]) command));
        } else if (command instanceof List) {
            @SuppressWarnings("unchecked")
            List<String> cmdList = (List<String>) command;
            rule.setCommand(String.join(" ", cmdList));
        }
        
        rule.setPermanent(permanent);
        return rule;
    }
    
    /**
     * 从复杂格式解析端口转发规则
     * 例如: "port=80:proto=tcp:toport=8080:toaddr=192.168.1.10"
     */
    public static ForwardPortRule parseForwardPortString(String zone, String forwardPortStr, boolean permanent) {
        Map<String, Object> data = new HashMap<>();
        data.put("zone", zone);
        
        // 解析格式类似 "port=80:proto=tcp:toport=8080:toaddr=192.168.1.10"
        String[] parts = forwardPortStr.split(":");
        for (String part : parts) {
            String[] keyValue = part.split("=");
            if (keyValue.length == 2) {
                String key = keyValue[0].trim();
                String value = keyValue[1].trim();
                
                // 映射到D-Bus参数名
                switch (key) {
                    case "port":
                        data.put("port", value);
                        break;
                    case "proto":
                        data.put("protocol", value);
                        break;
                    case "toport":
                        data.put("toport", value);
                        break;
                    case "toaddr":
                        data.put("toaddr", value);
                        break;
                }
            }
        }
        
        return createForwardPortRule(data, permanent);
    }
    
    /**
     * 从D-Bus返回的数据中解析端口及协议
     * 格式通常为 "8080/tcp"
     */
    public static PortRule parsePortString(String zone, String portStr, boolean permanent) {
        String[] parts = portStr.split("/");
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid port format: " + portStr);
        }
        
        Map<String, Object> data = new HashMap<>();
        data.put("zone", zone);
        data.put("port", parts[0].trim());
        data.put("protocol", parts[1].trim());
        
        return createPortRule(data, permanent);
    }
    
    /**
     * 安全获取字符串值
     */
    private static String getStringValue(Map<String, Object> data, String key) {
        return getStringValue(data, key, null);
    }
    
    /**
     * 安全获取字符串值，提供默认值
     */
    private static String getStringValue(Map<String, Object> data, String key, String defaultValue) {
        Object value = data.get(key);
        if (value == null) {
            return defaultValue;
        }
        return value.toString();
    }
    
    /**
     * 从D-Bus接口返回的原始数据创建规则对象
     * @param methodName D-Bus方法名，用于确定规则类型
     * @param data D-Bus返回的数据
     * @param zone 区域名称
     * @param permanent 是否永久规则
     * @return 对应的规则对象
     */
    public static FirewallRule createFromDBusMethodResult(String methodName, Object data, 
                                                         String zone, boolean permanent) {
        Map<String, Object> ruleData = new HashMap<>();
        ruleData.put("zone", zone);
        
        // 根据方法名确定规则类型并处理数据
        if (methodName.contains("service")) {
            ruleData.put("service", data.toString());
            return createServiceRule(ruleData, permanent);
        } else if (methodName.contains("port")) {
            // 处理可能的多种端口格式
            if (data instanceof String) {
                return parsePortString(zone, (String) data, permanent);
            } else if (data instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> portData = (Map<String, Object>) data;
                portData.put("zone", zone);
                return createPortRule(portData, permanent);
            }
        } else if (methodName.contains("forward_port")) {
            if (data instanceof String) {
                return parseForwardPortString(zone, (String) data, permanent);
            }
        } else if (methodName.contains("masquerade")) {
            ruleData.put("enabled", data);
            return createMasqueradeRule(ruleData, permanent);
        } else if (methodName.contains("rich_rule")) {
            ruleData.put("rule", data.toString());
            return createRichRule(ruleData, permanent);
        }
        // 其他规则类型处理...
        
        throw new IllegalArgumentException("Unsupported D-Bus method: " + methodName);
    }
}
