package cn.hedeoer.firewalld.firewalld.op;

import cn.hedeoer.common.entity.PortRule;
import cn.hedeoer.common.enmu.RuleType;
import cn.hedeoer.common.entity.SourceRule;
import cn.hedeoer.firewalld.PortRuleService;
import cn.hedeoer.firewalld.firewalld.exception.FirewallException;
import cn.hedeoer.pojo.PortInfo;
import cn.hedeoer.util.DeepCopyUtil;
import cn.hedeoer.util.IpUtils;
import cn.hedeoer.util.PortMonitorUtils;
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
import java.util.stream.Stream;

public class PortRuleServiceImplByFirewalld implements PortRuleService {
    private static final String FIREWALLD_PATH = "/org/fedoraproject/FirewallD1";
    private static final String FIREWALLD_BUS_NAME = "org.fedoraproject.FirewallD1";
    private static final Logger logger = LoggerFactory.getLogger(PortRuleServiceImplByFirewalld.class);

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
    public Boolean addOrRemoveOnePortRule(String zoneName, PortRule portRule, String operation)  {
        boolean res = false;
        try {
            res = false;
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
        } catch (FirewallException e) {
            throw new RuntimeException(e);
        }
        return res;
    }

    /**
     * 批量增加 或者 移除 端口规则
     * @param zoneName
     * @param portRules
     * @param operation
     * @return false 或者 true，需要由调用方根据返回值判断是否要加载firewalld使其 addOrRemoveBatchPortRules 生效
     */
    @Override
    public Boolean addOrRemoveBatchPortRules(String zoneName, List<PortRule> portRules, String operation)  {
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

    /**
     * 根据策略(policy)和使用状态(isUsing)查询指定防火墙区域的端口规则
     *
     * <p>此方法允许根据两个条件（策略和使用状态）对端口规则进行过滤查询。
     * 当任一参数为null时，表示不使用该条件进行过滤；当两个参数都为null时，
     * 返回指定区域的所有端口规则。</p>
     *
     * @param zoneName 防火墙区域名称，不能为null或空
     * @param isUsing 使用状态过滤条件，true表示查询正在使用的规则，false表示查询未使用的规则，null表示不过滤使用状态
     * @param policy 策略过滤条件，true表示查询允许(accept)策略的规则，false表示查询拒绝(reject)策略的规则，null表示不过滤策略
     * @return 符合条件的端口规则列表；如果没有符合条件的规则或查询出错，返回空列表
     */
    @Override
    public List<PortRule> queryPortRulesByPolicyAndUsingStatus(String zoneName, Boolean isUsing, Boolean policy) {
        // 参数验证
        if (zoneName == null || zoneName.trim().isEmpty()) {
            return Collections.emptyList(); // 或抛出异常
        }

        // 获取所有规则
        List<PortRule> allRules = queryAllPortRule(zoneName);
        if (allRules == null || allRules.isEmpty()) {
            return Collections.emptyList();
        }

        // 如果两个条件都为null，直接返回所有规则
        if (isUsing == null && policy == null) {
            logger.info("按照过滤条件：isUsing:{} ,policy:{} 过滤，都为null，将返回所有的端口规则",isUsing,policy);
            return allRules;
        }

        // 使用Stream API进行过滤
        Stream<PortRule> ruleStream = allRules.stream();

        // 根据policy过滤
        if (policy != null) {
            ruleStream = ruleStream.filter(rule -> policy.equals(rule.getPolicy()));
        }

        // 根据isUsing过滤
        if (isUsing != null) {
            ruleStream = ruleStream.filter(rule -> isUsing.equals(rule.getUsing()));
        }
        List<PortRule> collect = ruleStream.collect(Collectors.toList());
        logger.info("按照过滤条件：isUsing:{} ,policy:{} 过滤，命中{}条",isUsing,policy,collect.size());

        // 收集结果并返回
        return collect;
    }

    @Override
    public Boolean updateOnePortRule(String zoneName, PortRule oldPortRule, PortRule newPortRule)  {
        // 更新firewalld的一条端口规则：1. 删除原来的 2. 添加新的
        Boolean deleteRes = null;
        Boolean insertRes = null;
        deleteRes = addOrRemoveOnePortRule(zoneName, oldPortRule, "delete");
        insertRes = addOrRemoveOnePortRule(zoneName, newPortRule, "insert");
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
        
        // 增加判断是否具有对应防火墙zoneName的逻辑
        // 如果为新增时没有则创建，如果为删除或者查询时没有则报错
        boolean exist = ifExistZone(zoneName, operation);

        // 判断是添加还是移除操作
//        String operation ;
        // 构建 firewall-cmd 命令
        String command;
        // firewall-cmd 命令 list
        ArrayList<String> commandList = new ArrayList<>();

        // rich rule operation either add or remove
        operation = "insert".equals(operation) ? "add" : "remove";

        // 该条端口策略是否持久化
        Boolean permanent = portRule.isPermanent();

        // judge which simple operate or richRule operate ? if own sourceIps, it's richRule operate
        if (portRule.getSourceRule() != null && !"0.0.0.0".equals(portRule.getSourceRule().getSource())) {
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
                String permanentOpt = permanent ? " --permanent" : "";
                command = String.format("firewall-cmd --zone=%s --%s-rich-rule='%s' %s",
                        zoneName,
                        operation,
                        richRule,
                        permanentOpt);
                commandList.add(command);
            }

        } else {
            // PortRule的端口可能的形式
            // 单个端口，如：8080  firewall-cmd --zone=public --add-port=8080/tcp  --permanent
            //范围端口，如：3000-4000 firewall-cmd --add-port=3000-4000/tcp --permanent

            String permanentOpt = permanent ? " --permanent" : "";
            command = String.format("firewall-cmd --zone=%s --%s-port=%s/%s %s",
                    zoneName,
                    operation,
                    portRule.getPort(),
                    portRule.getProtocol().toLowerCase(),
                    permanentOpt);
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
                    .source("0.0.0.0")
                    .build();
            String des = "0.0.0.0";
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

            // 端口规则的描述
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


        // 补充 端口规则中端口的使用状态 和  iptype， zone，type，permanent（默认为永久生效）,端口规则的描述
        for (PortRule rule : distinctPortRules) {

            // 该条端口规则的端口，
            // 可能为单个端口，
            // 可能为-分隔区间端口，比如3434-4562；
            // 可能为,分隔区间端口2323，643534，22
            // 正常情况只有三种情况
            String port = rule.getPort();

            // 如果端口描述为默认值 0.0.0.0，则考虑使用端口监听的进程名字填充
            String descriptor = "0.0.0.0";

            // 端口规则中的状态列含义：
            // 当端口规则中端口为单个端口，比如 (tcp 4567)，using属性为true，表示该机器tcp下该端口正在被使用；为false，表示机器tcp的4567端口未被使用
            // 当端口规则为端口为多个端口，比如 tcp（3456-6543) 或者  udp[23423,553,774]）。using属性为true,表示机器tcp 的 3456-6543范围内有端口被使用了；为false,表示机器tcp 的 3456-6543范围内所有端口都未被占用
            // 具体端口使用详细信息查看PortInfoAdapter类实现
            List<PortInfo> portsInUse = PortMonitorUtils.getPortsInUse(port,rule.getProtocol());
            boolean inUse = !portsInUse.isEmpty();

            if (inUse) {
                StringBuilder stringBuilder = new StringBuilder();
                for (PortInfo portInfo : portsInUse) {
                    stringBuilder.append(portInfo.getProcessName()).append(",");
                }
                descriptor = stringBuilder.toString();
            }

            rule.setUsing(inUse);
            String ipType = IpUtils.getIpType(port);
            rule.setFamily(ipType);
            rule.setZone(zoneName);
            rule.setType(RuleType.PORT);
            rule.setDescriptor(descriptor);
            // todo 后续需要补充判断规则是否是永久生效的逻辑，目前默认永久生效
            rule.setPermanent(true);
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

    /**
     * 判断zone是否存在
     * 如果为新增时没有则创建，如果为删除或者查询时没有则报错
     * @param zoneName 需要判断的zone名字
     * @param operation 操作类型
     * @return true表示zone存在或已创建，false表示zone不存在且无法创建
     * @throws FirewallException 当zone不存在且为删除或查询操作时抛出异常
     */
    private boolean ifExistZone(String zoneName, String operation) throws FirewallException {
        try {
            // 获取DBus连接
            DBusConnection connection = FirewallDRuleQuery.getDBusConnection();

            // 获取zone接口
            FirewallDRuleQuery.FirewallDZoneInterface zoneInterface = connection.getRemoteObject(
                    FIREWALLD_BUS_NAME,
                    FIREWALLD_PATH,
                    FirewallDRuleQuery.FirewallDZoneInterface.class);

            // 获取所有zones
            List<String> zones = Arrays.asList(zoneInterface.getZones());

            // 检查zone是否存在
            boolean exists = zones.contains(zoneName);

            if (!exists) {
                // 如果是insert操作且zone不存在，尝试创建zone
                if ("insert".equals(operation)) {
                    String command = String.format("firewall-cmd --permanent --new-zone=%s", zoneName);
                    ProcessResult result = new ProcessExecutor()
                            .command("/bin/bash", "-c", command)
                            .readOutput(true)
                            .timeout(30, TimeUnit.SECONDS)
                            .execute();

                    if (result.getExitValue() == 0) {
                        // 创建成功后需要重新加载
                        String reloadCommand = "firewall-cmd --reload";
                        result = new ProcessExecutor()
                                .command("/bin/bash", "-c", reloadCommand)
                                .readOutput(true)
                                .timeout(30, TimeUnit.SECONDS)
                                .execute();

                        return result.getExitValue() == 0;
                    }
                    return false;
                } else {
                    // 如果是delete或query操作且zone不存在，抛出异常
                    throw new FirewallException(String.format("Zone %s does not exist", zoneName));
                }
            }

            return true;
        } catch (DBusException | IOException | InterruptedException | TimeoutException e) {
            throw new FirewallException("Failed to check zone existence: " + e.getMessage(), e);
        }
    }

}
