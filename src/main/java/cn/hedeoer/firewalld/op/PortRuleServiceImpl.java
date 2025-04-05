package cn.hedeoer.firewalld.op;

import cn.hedeoer.firewalld.PortRule;
import cn.hedeoer.firewalld.SourceRule;
import cn.hedeoer.firewalld.exception.FirewallException;
import cn.hedeoer.pojo.FireWallType;
import cn.hedeoer.util.DeepCopyUtil;
import cn.hedeoer.util.IpUtils;
import cn.hedeoer.util.PortUsageUtil;
import cn.hedeoer.util.WallUtil;
import org.freedesktop.dbus.annotations.DBusInterfaceName;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.interfaces.DBusInterface;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zeroturnaround.exec.ProcessExecutor;
import org.zeroturnaround.exec.ProcessResult;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;

public class PortRuleServiceImpl implements PortRuleService {
    private static final String FIREWALLD_PATH = "/org/fedoraproject/FirewallD1";
    private static final String FIREWALLD_BUS_NAME = "org.fedoraproject.FirewallD1";
    private static final Logger logger = LoggerFactory.getLogger(PortRuleServiceImpl.class);

    /**
     * 获取某个zone内所有的端口规则
     *
     * @param zoneName zone名字
     * @return
     */
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

    /**
     * 增加或者删除一条端口规则
     * @param zoneName zone名字
     * @param portRule 端口规则
     * @param operation portRule operation (insert or delete)
     * @return false 或者 true，需要由调用方根据返回值判断是否要加载firewalld使其addOrRemoveOnePortRule生效
     * @throws FirewallException
     */
    @Override
    public Boolean addOrRemoveOnePortRule(String zoneName, PortRule portRule, String operation) throws FirewallException {
        boolean res = false;
        if(portRule.getProtocol() == null || portRule.getPort() == null) return res;

        String[] protocolSplit = portRule.getProtocol().split("/");
        String[] portSplit = portRule.getPort().split(",");
        boolean isMultiProtocol = protocolSplit.length > 1;
        boolean isMultiPort = portSplit.length > 1;
        // 判断是否 portRule 的 port为 ,分隔多个端口
        if (isMultiPort) {
            // 多端口 单协议
            if(!isMultiProtocol) {
                res = addOrRemovePortRuleByMultiPort(zoneName, portRule, operation);
            }else {
                // 多端口 多协议
                res = addOrRemovePortRuleByMultiPortAndMultiProtocol(zoneName, portRule, operation);
            }

        } else {
            // 单个端口 单协议
            if (!isMultiProtocol) {
                res = addOrRemovePortRule(zoneName, portRule, operation);
            }else {
                // 单个端口 多协议
                res = addOrRemovePortRuleByMultiProtocol(zoneName, portRule, operation);
            }
        }
        return res;
    }

    /**
     * 批量增加 或者 移除 端口规则
     * @param zoneName
     * @param portRules
     * @param operation
     * @return false 或者 true，需要由调用方根据返回值判断是否要加载firewalld使其 addOrRemoveBatchPortRules 生效
     * @throws FirewallException
     */
    @Override
    public Boolean addOrRemoveBatchPortRules(String zoneName, List<PortRule> portRules, String operation) throws FirewallException {
        boolean flag = true;
        // 多次调用
        for (PortRule portRule : portRules) {
            boolean a = addOrRemoveOnePortRule(zoneName,portRule,operation);
            if (!a){
                flag = false;
                break;
            }
        }
        return flag;
    }

    @Override
    public List<PortRule> queryPortRulesByUsingStatus(String zoneName, Boolean isUsing) {
        List<PortRule> rules = queryAllPortRule(zoneName);
        return rules.stream()
                .filter(rule -> isUsing.equals(rule.getUsing()))
                .collect(Collectors.toList());
    }

    @Override
    public List<PortRule> queryPortRulesByPolicy(String zoneName, Boolean policy) {
        List<PortRule> rules = queryAllPortRule(zoneName);
        return rules.stream()
                .filter(rule -> policy.equals(rule.getPolicy()))
                .collect(Collectors.toList());
    }

    @Override
    public Boolean updateOnePortRule(String zoneName, PortRule oldPortRule, PortRule newPortRule) throws FirewallException {
        // 更新firewalld的一条端口规则：1. 删除原来的 2. 添加新的
        Boolean deleteRes = addOrRemovePortRule(zoneName, oldPortRule, "delete");
        Boolean insertRes = addOrRemovePortRule(zoneName, newPortRule, "insert");
        return deleteRes && insertRes;
    }

    /**
     * 多端口多协议
     *
     * @param zoneName
     * @param portRule
     * @param operation
     * @return
     */
    private Boolean addOrRemovePortRuleByMultiPortAndMultiProtocol(String zoneName, PortRule portRule, String operation) throws FirewallException {
        boolean res = true;
        String[] protocolSplit = portRule.getProtocol().split("/");
        String[] portSplit = portRule.getPort().split(",");
        if (protocolSplit.length > 1 && portSplit.length > 1) {
            for (String protocolName : protocolSplit) {
                for (String port : portSplit) {
                    PortRule tmpPortRule = PortRule.builder()
                            .protocol(protocolName)
                            .port(port)
                            .sourceRule(portRule.getSourceRule())
                            .policy(portRule.getPolicy())
                            .descriptor(portRule.getDescriptor())
                            .build();
                    Boolean aBoolean = addOrRemovePortRule(zoneName, tmpPortRule, operation);
                    if (!aBoolean){
                        res = false;
                        break;
                    }
                }
            }

        }
        return res;
    }

    private Boolean addOrRemovePortRule(String zoneName, PortRule portRule, String operation) throws FirewallException {

        boolean addOrRemovePortRuleResult = false;

        // 参数校验
        if (!("insert".equals(operation) || "delete".equals(operation)) && portRule == null || WallUtil.isIllegal(portRule.getPort(), portRule.getProtocol())) {
            throw new FirewallException("Invalid port rule parameters");
        }

        // 判断是添加还是移除操作
//        String operation ;
        // 构建 firewall-cmd 命令
        String command;
        // firewall-cmd 命令 list
        ArrayList<String> commandList = new ArrayList<>();

        // rich rule operation either add or remove
        operation = "insert".equals(operation) ? "add" : "remove";

        // judge which simple operate or richRule operate ? if own sourceIps, it's richRule operate
        if (portRule.getSourceRule() != null) {
            String sourceIps = portRule.getSourceRule().getSource();
            // need check sourceIps formater
            List<IpUtils.IpInfo> sourceIpInfos = IpUtils.parseIpAddresses(sourceIps);
            String policy;
            for (IpUtils.IpInfo sourceIpinfo : sourceIpInfos) {
                String sourceIp = sourceIpinfo.getAddress();
                // get ip type (ipv4 or ipv6)
                String ipType = IpUtils.getIpType(portRule.getPort());
                // rich rule policy either accept or reject
                policy = portRule.getPolicy() != null && portRule.getPolicy() ? "accept" : "reject";

                // 构建富规则命令
                String richRule = String.format("rule family=\"%s\" source address=\"%s\" port port=\"%s\" protocol=\"%s\" %s",
                        ipType,
                        sourceIp,
                        portRule.getPort(),
                        portRule.getProtocol().toLowerCase(),
                        policy);

                // 添加或移除富规则
                command = String.format("firewall-cmd --zone=%s --%s-rich-rule='%s' --permanent",
                        zoneName,
                        operation,
                        richRule);
                commandList.add(command);
            }

        } else {
            // PortRule的端口可能的形式
            // 单个端口，如：8080  firewall-cmd --zone=public --add-port=8080/tcp  --permanent
            //范围端口，如：3000-4000 firewall-cmd --add-port=3000-4000/tcp --permanent

            command = String.format("firewall-cmd --zone=%s --%s-port=%s/%s --permanent",
                    zoneName,
                    operation,
                    portRule.getPort(),
                    portRule.getProtocol().toLowerCase());
            commandList.add(command);
        }


        try {
            boolean allSucess = true;
            ProcessResult result = null;
            String combinedCommand = String.join(" ; ", commandList);

            logger.info("will execute firewall command : {}", combinedCommand);
            // 执行命令
            result = new ProcessExecutor()
                    .command("/bin/bash", "-c", combinedCommand)
                    .readOutput(true)
                    .timeout(30, TimeUnit.SECONDS)
                    .execute();
            if (result.getExitValue() != 0) {
                allSucess = false;
            }


            // 检查执行结果(return true and if all pass)
            if (!allSucess) {
                String errorOutput = result.outputUTF8();
                throw new FirewallException(String.format("Zone : %s, operation port: %s/%s failed, error: %s",
                        zoneName,
                        portRule.getPort(),
                        portRule.getProtocol(),
                        errorOutput));
            }else {
                addOrRemovePortRuleResult = true;
            }
            return addOrRemovePortRuleResult;
        } catch (IOException | InterruptedException | TimeoutException e) {
            throw new FirewallException("Failed to execute firewall command: " + e.getMessage(), e);
        } catch (FirewallException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 多端口，单协议
     *
     * @param zoneName
     * @param portRule
     * @param operation
     * @return
     * @throws FirewallException
     */
    private Boolean addOrRemovePortRuleByMultiPort(String zoneName, PortRule portRule, String operation) throws FirewallException {
        boolean allDone = true;
        String port = portRule.getPort();
        String[] split = port.split(",");
        String[] split1 = portRule.getProtocol().split("/");
        if (split.length > 1 && split1.length == 1) {
            for (String s : split) {
                Boolean aBoolean = addOrRemovePortRule(zoneName,
                        PortRule.builder()
                                .protocol(portRule.getProtocol())
                                .port(s)
                                .sourceRule(portRule.getSourceRule())
                                .policy(portRule.getPolicy())
                                .descriptor(portRule.getDescriptor())
                                .build(),
                        operation);
                if (!aBoolean) {
                    allDone = false;
                    // 如果有一条没有执行成功，中止后续行为
                    break;
                }
            }
        }

        return allDone;
    }

    /**
     * 多协议单端口
     *
     * @param zoneName
     * @param portRule
     * @param operation
     * @return
     * @throws FirewallException
     */
    private Boolean addOrRemovePortRuleByMultiProtocol(String zoneName, PortRule portRule, String operation) throws FirewallException {
        boolean allDone = true;
        String[] split = portRule.getProtocol().split("/");
        String[] split1 = portRule.getPort().split(",");
        int length = split.length;
        if (length > 1 && split1.length == 1) {
            for (String s : split) {
                Boolean aBoolean = addOrRemovePortRule(zoneName,
                        PortRule.builder()
                                .protocol(s)
                                .port(portRule.getPort())
                                .sourceRule(portRule.getSourceRule())
                                .policy(portRule.getPolicy())
                                .descriptor(portRule.getDescriptor())
                                .build(),
                        operation);
                if (!aBoolean) {
                    allDone = false;
                }
            }
        }
        return allDone;
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

        HashSet<PortRule> distinctPortRules = new HashSet<>();
        // 先添加 从富规则中提取的，如果后面有”重复“的，就不会添加成功，以从富规则中提取的为准
        distinctPortRules.addAll(portRulesFromRichRules);
        // 后添加从 dbus查询的
        distinctPortRules.addAll(portRulesFromDbusPortQuery);
        logger.info("当前zone: {},从富规则中提取的端口规则有portRulesFromRichRules {} 条 :", zoneName, portRulesFromRichRules.size());
        logger.info("当前zone: {},从dbus端口查询中提取的端口规则有portRulesFromDbusPortQuery {} 条 :", zoneName, portRulesFromDbusPortQuery.size());


        // 补充 端口规则中端口的使用状态 and  iptype
        for (PortRule rule : distinctPortRules) {
            String processCommandName = PortUsageUtil.getProcessCommandName(Integer.parseInt(rule.getPort()));
            // 检查端口是否被进程使用中
            boolean enabled = processCommandName != null;
//            boolean enabled = zoneInterface.queryPort(zoneName, rule.getPort(), rule.getProtocol());
            rule.setUsing(enabled);
            String ipType = IpUtils.getIpType(rule.getPort());
            rule.setFamily(ipType);
        }

        // PortRule{port='9999', protocol='tcp', using=false, policy=true, sourceRule=SourceRule(source=172.16.0.99), descriptor='All IPs allowed'}
        // PortRule{port='9999', protocol='udp', using=false, policy=true, sourceRule=SourceRule(source=172.16.0.99), descriptor='All IPs allowed'}
        // 合并为 PortRule{port='9999', protocol='tcp/udp', using=false, policy=true, sourceRule=SourceRule(source=172.16.0.99), descriptor='All IPs allowed'}
        // 使用 Stream 合并相同端口的 TCP/UDP 规则
        Set<PortRule> mergedSet = distinctPortRules.stream()
                // 1. 按port, using, sourceRule, descriptor分组
                .collect(Collectors.groupingBy(rule -> Arrays.asList(
                        rule.getPort(),
                        rule.getUsing(),
                        rule.getSourceRule().getSource(),
                        rule.getDescriptor()
                )))
                .values().stream() // 处理每个分组
                // 2. 对每组内的规则进行处理
                .map(rules -> {
                    // 如果组内只有一个规则，直接返回
                    if (rules.size() == 1) {
                        return rules.get(0);
                    }

                    // 检查是否同时存在TCP和UDP
                    boolean hasTcp = rules.stream().anyMatch(r -> "tcp".equals(r.getProtocol()));
                    boolean hasUdp = rules.stream().anyMatch(r -> "udp".equals(r.getProtocol()));

                    if (hasTcp && hasUdp) {
                        // 获取组内第一个规则作为基础
                        PortRule baseRule = rules.get(0);
                        // 创建一个新对象，或复制现有对象 (取决于PortRule类的实现)
                        PortRule mergeRule = DeepCopyUtil.deepCopy(baseRule, PortRule.class);
                        mergeRule.setProtocol("tcp/udp");
                        return mergeRule;
                    } else {
                        // 如果不是TCP/UDP组合，返回第一个规则
                        return rules.get(0);
                    }
                })
                .collect(Collectors.toSet());
        logger.info("当前zone: {},按照（端口号，端口协议）去重，优先富规则形式，合并端口规则后有 {} 条 :", zoneName, mergedSet.size());

        return new ArrayList<>(mergedSet);
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

}
