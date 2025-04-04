package cn.hedeoer.firewalld.op;

import cn.hedeoer.firewalld.PortRule;
import cn.hedeoer.firewalld.SourceRule;
import org.freedesktop.dbus.annotations.DBusInterfaceName;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.interfaces.DBusInterface;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;

public class PortRuleServiceImpl implements PortRuleService {
    private static final String FIREWALLD_PATH = "/org/fedoraproject/FirewallD1";
    private static final String FIREWALLD_BUS_NAME = "org.fedoraproject.FirewallD1";
    private static final Logger logger = LoggerFactory.getLogger(PortRuleServiceImpl.class);

    @Override
    public List<PortRule> queryAllPortRule(String zoneName) {
        ArrayList<PortRule> portRules = new ArrayList<>();
        try {
            // 首先判断zone是否存在

            // 查询zone下所有端口信息
            DBusConnection dBusConnection = FirewallDRuleQuery.getDBusConnection();

/*            // 获取firewalld服务的对象
            String serviceName = "org.fedoraproject.FirewallD1";
            String zonePath = "/org/fedoraproject/FirewallD1/zone/" + zoneName;
            // 获取Zone对象
            ZoneInterface zoneInterface = dBusConnection.getRemoteObject(serviceName, zonePath, ZoneInterface.class);*/

            ZoneInterface zoneInterface = dBusConnection.getRemoteObject(
                    FIREWALLD_BUS_NAME,
                    FIREWALLD_PATH,
                    ZoneInterface.class);
            portRules = getPortRule(zoneInterface, zoneName);
        } catch (DBusException e) {
            throw new RuntimeException(e);
        }

        return portRules;
    }

    private ArrayList<PortRule> getPortRule(ZoneInterface zoneInterface, String zoneName) {
        // 获取所有端口配置
        String[][] portArray = zoneInterface.getPorts(zoneName);

        // 获取富规则（用于获取更详细的配置）
        String[] richRules = zoneInterface.getRichRules(zoneName);
        // 解析富规则文本获得端口对应的源ip，规则策略，可能需要去重
        Set<FirewallRuleParser.ParsedRule> portWithSourceAndPolicySet = new HashSet<>();
        for (String richRule : richRules) {
            portWithSourceAndPolicySet.addAll(FirewallRuleParser.parseFirewallRule(richRule));
        }

        // 合并具有端口配置的 端口 和 富规则中提取的端口
        List<PortRule> portRulesFromDbusPortQuery = new ArrayList<>();
        for (int i = 0; i < portArray.length; i++) {
            String protocol = portArray[i][1];
            String portNumber = portArray[i][0];
            boolean using = false;
            boolean policy = true;
            SourceRule sourceRule = SourceRule.builder()
                    .source("All IPs allowed")
                    .build();
            String des = "All IPs allowed";
            PortRule portRule = PortRule.builder()
                    .port(portNumber)
                    .protocol(protocol)
                    .using(using)
                    .policy(policy)
                    .sourceRule(sourceRule)
                    .descriptor(des)
                    .build();
            portRulesFromDbusPortQuery.add(portRule);
        }

        List<PortRule> portRulesFromRichRules = new ArrayList<>();
        for (FirewallRuleParser.ParsedRule parsedRule : portWithSourceAndPolicySet) {
            String protocol = parsedRule.getProtocol();
            String portNumber = parsedRule.getPort();
            boolean using = false;
            boolean policy = "accept".equals(parsedRule.getPolicy());

            SourceRule sourceRule = SourceRule.builder()
                    .source(parsedRule.getSource())
                    .build();
            String des = parsedRule.getDescription();
            PortRule portRule = PortRule.builder()
                    .port(portNumber)
                    .protocol(protocol)
                    .using(using)
                    .policy(policy)
                    .sourceRule(sourceRule)
                    .descriptor(des)
                    .build();
            portRulesFromRichRules.add(portRule);
        }

        HashSet<PortRule> distinctPortRules = new HashSet<>(){};
        // 先添加 从富规则中提取的，如果后面有”重复“的，就不会添加成功，以从富规则中提取的为准
        distinctPortRules.addAll(portRulesFromRichRules);
        // 后添加从 dbus查询的
        distinctPortRules.addAll(portRulesFromDbusPortQuery);
        logger.info("当前zone: {},从富规则中提取的端口规则有portRulesFromRichRules {} 条 :", zoneName,portRulesFromRichRules.size());
        logger.info("当前zone: {},从dbus端口查询中提取的端口规则有portRulesFromDbusPortQuery {} 条 :", zoneName,portRulesFromDbusPortQuery.size());
        logger.info("当前zone: {},按照（端口号，端口协议）去重，优先富规则形式，合并端口规则后有 {} 条 :", zoneName,distinctPortRules.size());

        // 补充 端口规则中端口的使用状态
        for (PortRule rule : distinctPortRules) {
            // 检查端口状态
            boolean enabled = zoneInterface.queryPort(zoneName, rule.getPort(), rule.getProtocol());
            rule.setUsing(enabled);
        }

        /*     // 处理获取的端口信息
        for (int i = 0; i < portArray.length; i++) {
            // 格式如 "[22, tcp]"
            String protocol = portArray[i][1];
            String portNumber = portArray[i][0];

            // 检查端口状态
            boolean enabled = zoneInterface.queryPort(zoneName, portNumber, protocol);

            logger.info("端口: {}", portNumber);
            logger.info("协议: {}", protocol);
            logger.info("状态: {}", enabled ? "已使用" : "未使用");


            // 从富规则中查找与此端口相关的规则
            for (FirewallRuleParser.ParsedRule parsedRule : portWithSourceAndPolicySet) {
                // 默认端口规则为accept,除非富规则中改动
                boolean policy = true;

                // 端口默认描述为 All IPs allowed, 除非富规则中改动
                String description = "All IPs allowed";

                // 端口默认sourceIP为 All IPs allowed,即不限制
                String sourceIPs = "All IPs allowed";
                if (portNumber.equals(parsedRule.getPort()) && protocol.equals(parsedRule.getProtocol())){

                    sourceIPs = parsedRule.getSource();
                    SourceRule sourceRule = SourceRule.builder()
                            .source(sourceIPs)
                            .build();

                    String fromRichRulePolicy = parsedRule.getPolicy();
                    if ("reject".equals(fromRichRulePolicy) || "drop".equals(fromRichRulePolicy)) {
                        policy = false;
                    }

                    // 端口默认描述为 All IPs allowed
                    description = parsedRule.getDescription();

                    PortRule portRule = PortRule.builder()
                            .port(portNumber)
                            .protocol(protocol)
                            .using(enabled)
                            .policy(policy)
                            .sourceRule(sourceRule)
                            .descriptor(description)
                            .build();
                    portRules.add(portRule);
                }
                logger.info("策略: {}", policy);
                logger.info("源IP: {}", sourceIPs);
                logger.info("描述: {}", description);
            }
        }*/

        return new ArrayList<>(distinctPortRules);
    }

    @DBusInterfaceName("org.fedoraproject.FirewallD1.zone")
    interface ZoneInterface extends DBusInterface {

        // 获取所有端口
        String[][] getPorts(String zone);

        // 查询特定端口
        boolean queryPort(String zone, String port, String protocol);

        // 获取富规则
        String[] getRichRules(String zone);

        // 获取源端口
        String[][] getSourcePorts(String zone);
    }

    public static void main(String[] args) {
        PortRuleServiceImpl service = new PortRuleServiceImpl();
        List<PortRule> rules = service.queryAllPortRule("public");
        for (PortRule rule : rules) {
            logger.info(rule.toString());
        }

    }
}
