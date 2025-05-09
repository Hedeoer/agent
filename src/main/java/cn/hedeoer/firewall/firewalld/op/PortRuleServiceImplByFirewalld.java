package cn.hedeoer.firewall.firewalld.op;

import cn.hedeoer.common.entity.PortRule;
import cn.hedeoer.common.enmu.RuleType;
import cn.hedeoer.common.entity.SourceRule;
import cn.hedeoer.firewall.PortRuleService;
import cn.hedeoer.firewall.firewalld.exception.FirewallException;
import cn.hedeoer.pojo.PortInfo;
import cn.hedeoer.util.*;
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
    private static final Logger logger = LoggerFactory.getLogger(PortRuleServiceImplByFirewalld.class);

    /**
     * 获取某个zone内所有的端口规则
     *
     * @param zoneName zone名字
     * @return
     */
    @Override
    public List<PortRule> queryAllPortRule(String zoneName) {
        return queryAllPortRuleByParseCommand(zoneName);
    }

    /**
     * 增加或者删除一条端口规则
     *
     * @param zoneName  zone名字
     * @param portRule  端口规则
     * @param operation portRule operation (insert or delete)
     * @return false 或者 true，需要由调用方根据返回值判断是否要加载firewalld使其addOrRemoveOnePortRule生效
     * @throws FirewallException
     */
    @Override
    public Boolean addOrRemoveOnePortRule(String zoneName, PortRule portRule, String operation) {
        boolean res = false;
        try {
            res = false;
            if (portRule.getProtocol() == null || portRule.getPort() == null) return res;

            String[] protocolSplit = portRule.getProtocol().split("/");
            String[] portSplit = portRule.getPort().split(",");
            boolean isMultiProtocol = protocolSplit.length > 1;
            boolean isMultiPort = portSplit.length > 1;
            // 判断是否 portRule 的 port为 ,分隔多个端口
            if (isMultiPort) {
                // 多端口 单协议
                if (!isMultiProtocol) {
                    res = addOrRemovePortRuleByMultiPort(zoneName, portRule, operation);
                } else {
                    // 多端口 多协议
                    res = addOrRemovePortRuleByMultiPortAndMultiProtocol(zoneName, portRule, operation);
                }

            } else {
                // 单个端口 单协议
                if (!isMultiProtocol) {
                    res = addOrRemovePortRule(zoneName, portRule, operation);
                } else {
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
     *
     * @param zoneName
     * @param portRules
     * @param operation
     * @return false 或者 true，需要由调用方根据返回值判断是否要加载firewalld使其 addOrRemoveBatchPortRules 生效
     */
    @Override
    public Boolean addOrRemoveBatchPortRules(String zoneName, List<PortRule> portRules, String operation) {
        boolean flag = true;
        // 多次调用
        for (PortRule portRule : portRules) {
            boolean a = addOrRemoveOnePortRule(zoneName, portRule, operation);
            if (!a) {
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
     * @param isUsing  使用状态过滤条件，true表示查询正在使用的规则，false表示查询未使用的规则，null表示不过滤使用状态
     * @param policy   策略过滤条件，true表示查询允许(accept)策略的规则，false表示查询拒绝(reject)策略的规则，null表示不过滤策略
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
            logger.info("按照过滤条件：isUsing:{} ,policy:{} 过滤，都为null，将返回所有的端口规则", isUsing, policy);
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
        logger.info("按照过滤条件：isUsing:{} ,policy:{} 过滤，命中{}条", isUsing, policy, collect.size());

        // 收集结果并返回
        return collect;
    }

    @Override
    public Boolean updateOnePortRule(String zoneName, PortRule oldPortRule, PortRule newPortRule) {
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
                    if (!aBoolean) {
                        res = false;
                        break;
                    }
                }
            }

        }
        return res;
    }

    /**
     * 在指定的 firewalld 区域中添加或删除端口规则（支持普通规则和富规则）。
     * <p>
     * 此方法负责根据提供的 {@code portRule} 对象和 {@code operation} 类型，
     * 通过执行 `firewall-cmd` 命令来管理防火墙规则。
     * 主要功能包括：
     * <ul>
     * <li>参数校验。</li>
     * <li>检查目标区域是否存在，如果不存在且操作为添加，则尝试创建该区域。</li>
     * <li>根据 {@code portRule} 的属性（如源IP、端口、协议、策略、持久化、IP族）构建相应的 `firewall-cmd` 命令。</li>
     * <li>支持处理 IPv4、IPv6 或同时处理两种 IP 协议族 ("ipv4/ipv6") 的规则。</li>
     * <li>处理简单规则和带有源地址限制的富规则。</li>
     * <li>执行构建好的命令，并检查返回码以确定操作是否成功（特定返回码如 ALREADY_ENABLED 或 NOT_ENABLED 也视为成功）。</li>
     * <li>如果规则是持久化的 (permanent)，则在操作成功后重新加载防火墙配置。</li>
     * <li>针对简单规则的删除操作，会特殊处理以确保只移除指定IP族的规则（通过弥补操作，因为`--remove-port`会同时移除v4和v6）。</li>
     * </ul>
     *
     * @param zoneName 要操作的 firewalld 区域的名称 (例如 "public", "internal")。不能为空。
     * @param portRule 包含端口规则详细信息的对象。必须包含有效的端口和协议。
     * 其属性包括：
     * <ul>
     * <li>{@code port}: 端口号。</li>
     * <li>{@code protocol}: 协议 (例如 "tcp", "udp")。</li>
     * <li>{@code sourceRule}: (可选) 源地址规则。如果提供且源地址非 "0.0.0.0"，则创建富规则。</li>
     * <li>{@code policy}: (可选, 默认为 accept) 规则策略，true 代表 "accept"，false 代表 "reject"。</li>
     * <li>{@code permanent}: 规则是否为持久化的。true 表示永久规则，false 表示运行时规则。</li>
     * <li>{@code family}: IP 协议族 ("ipv4", "ipv6", 或 "ipv4/ipv6")。</li>
     * </ul>
     * @param operation 要执行的操作，必须是 "insert" (添加) 或 "delete" (删除)。
     * @return 如果操作成功执行（包括规则已存在于添加操作，或规则不存在于删除操作等幂等情况），则返回 {@code true}。
     * @throws FirewallException 如果发生以下任一情况：
     * <ul>
     * <li>输入参数无效（例如 {@code portRule} 为 null，操作不是 "insert" 或 "delete"，端口/协议无效）。</li>
     * <li>检查或创建防火墙区域时失败。</li>
     * <li>尝试删除规则时，指定的区域不存在。</li>
     * <li>执行 `firewall-cmd` 命令失败，并返回了非预期（非 0, 11, 12, 16, 34）的退出码。</li>
     * <li>重新加载防火墙配置失败（仅当规则是持久化时）。</li>
     * <li>在执行外部进程时发生 {@link java.io.IOException}、{@link java.lang.InterruptedException} 或 {@link java.util.concurrent.TimeoutException}。</li>
     * </ul>
     */
    private Boolean addOrRemovePortRule(String zoneName, PortRule portRule, String operation) throws FirewallException {
        // 参数校验
        if (portRule == null || !("insert".equals(operation) || "delete".equals(operation)) ||
                WallUtil.isIllegal(portRule.getPort(), portRule.getProtocol())) {
            throw new FirewallException("Invalid port rule parameters");
        }

        // 检查防火墙zone是否存在
        try {
            ProcessResult zoneCheckResult = new ProcessExecutor()
                    .command("/bin/bash", "-c", "firewall-cmd --get-zones")
                    .readOutput(true)
                    .execute();

            if (zoneCheckResult.getExitValue() != 0) {
                throw new FirewallException("Failed to check firewall zones");
            }

            String zones = zoneCheckResult.outputUTF8();
            boolean zoneExists = Arrays.asList(zones.split("\\s+")).contains(zoneName);

            // 如果是删除操作但zone不存在，则报错
            if ("delete".equals(operation) && !zoneExists) {
                throw new FirewallException("Zone " + zoneName + " does not exist");
            }

            // 如果是新增操作但zone不存在，则创建zone
            if ("insert".equals(operation) && !zoneExists) {
                ProcessResult createZoneResult = new ProcessExecutor()
                        .command("/bin/bash", "-c", "firewall-cmd --permanent --new-zone=" + zoneName + " && firewall-cmd --reload")
                        .readOutput(true)
                        .execute();

                if (createZoneResult.getExitValue() != 0) {
                    throw new FirewallException("Failed to create zone " + zoneName + ": " + createZoneResult.outputUTF8());
                }
            }
        } catch (IOException | InterruptedException | TimeoutException e) {
            throw new FirewallException("Failed to check or create firewall zone: " + e.getMessage(), e);
        }

        // 转换操作名称为firewall-cmd命令格式
        String cmdOperation = "insert".equals(operation) ? "add" : "remove";

        // 该条端口策略是否持久化
        Boolean permanent = portRule.isPermanent();
        String permanentOpt = permanent ? " --permanent" : "";

        // 构建命令列表
        List<String> commandList = new ArrayList<>();

        // 是否允许多ip协议族访问
        String family = portRule.getFamily();
        boolean isMultiFamily = "ipv4/ipv6".equals(family);

        // 判断是富规则还是简单规则
        if (portRule.getSourceRule() != null && !"0.0.0.0".equals(portRule.getSourceRule().getSource())) {
            // 富规则操作 - 有源IP地址限制
            String sourceIps = portRule.getSourceRule().getSource();
            List<IpUtils.IpInfo> sourceIpInfos = IpUtils.parseIpAddresses(sourceIps);
            String policy = portRule.getPolicy() != null && portRule.getPolicy() ? "accept" : "reject";

            for (IpUtils.IpInfo sourceIpinfo : sourceIpInfos) {
                String sourceIp = sourceIpinfo.getAddress();

                String command = "";
                String oppFamily = "ipv4".equals(family) ? "ipv6" : "ipv4";
                // 构建富规则
                String richRule = String.format("rule family=\"%s\" source address=\"%s\" port port=\"%s\" protocol=\"%s\" %s",
                        family, sourceIp, portRule.getPort(), portRule.getProtocol().toLowerCase(), policy);

                // 添加或移除富规则命令
                command = String.format("firewall-cmd --zone=%s --%s-rich-rule='%s'%s",
                        zoneName, cmdOperation, richRule, permanentOpt);

                // 多个ip协议族支持的话，需要执行两条语句
                if (isMultiFamily) {
                    String ipv4Command = command.replace("ipv4/ipv6", "ipv4");
                    String ipv6Command = ipv4Command.replace("ipv4", "ipv6");
                    commandList.add(ipv4Command);
                    commandList.add(ipv6Command);
                }else{
                    commandList.add(command);
                }
            }
        } else {
            // 简单规则操作 - 无源IP地址限制
            String policy = Boolean.TRUE.equals(portRule.getPolicy()) ? "accept" : "reject";

            if ("add".equals(cmdOperation)) {
                // 添加端口规则
                String richRuleCommand = String.format(
                        "firewall-cmd --zone=%s --add-rich-rule='rule family=\"%s\" port port=\"%s\" protocol=\"%s\" %s'%s",
                        zoneName, family, portRule.getPort(),
                        portRule.getProtocol().toLowerCase(), policy, permanentOpt);

                // 多个ip协议族支持的话，需要执行两条语句
                if (isMultiFamily) {
                    String ipv4Command = richRuleCommand.replace("ipv4/ipv6", "ipv4");
                    String ipv6Command = ipv4Command.replace("ipv4", "ipv6");
                    commandList.add(ipv4Command);
                    commandList.add(ipv6Command);
                }else{
                    commandList.add(richRuleCommand);
                }

            } else {
                // 移除端口规则
                // 移除简单端口规则
                String portCommand = String.format(
                        "firewall-cmd --zone=%s --remove-port=%s/%s%s",
                        zoneName, portRule.getPort(), portRule.getProtocol().toLowerCase(), permanentOpt);

                commandList.add(portCommand);

                // portCommand 执行同时移除了ipv4 和  ipv6规则，需要做弥补操作
                String makeUpForType = "ipv4".equals(family) ? "ipv6" : "ipv4";
                String richRuleCommand = String.format(
                        "firewall-cmd --zone=%s --add-rich-rule='rule family=\"%s\" port port=\"%s\" protocol=\"%s\" %s'%s",
                        zoneName, makeUpForType, portRule.getPort(),
                        portRule.getProtocol().toLowerCase(), policy, permanentOpt);

                commandList.add(richRuleCommand);
            }
        }

        // 执行命令
        try {
            String combinedCommand = String.join(" && ", commandList);
            logger.info("Executing firewall command: {}", combinedCommand);

            ProcessResult result = new ProcessExecutor()
                    .command("/bin/bash", "-c", combinedCommand)
                    .readOutput(true)
                    .timeout(30, TimeUnit.SECONDS)
                    .execute();

            // 什么是序列选项 (Sequence Options): 指那些可以在一条命令里多次指定的选项。例如，你可以在一条命令里用 --add-port= 添加好几个端口，或者用 --add-rich-rule= 添加好几条富规则。
            //成功条件 (Exit Code 0): 只要这些多个操作中至少有一个成功执行了，那么整个 firewall-cmd 命令就会返回退出码 0，表示成功。
            // 特殊“成功”情况:
            //ALREADY_ENABLED (11): 你想添加的东西（规则、端口、服务等）已经存在了。（就像你之前遇到的情况）
            //NOT_ENABLED (12): 你想移除的东西（规则、端口、服务等）其实原本就不存在。
            //ZONE_ALREADY_SET (16): 你想把接口或源设置到某个区域，但它其实已经被设置到那个区域了。
            //ALREADY_SET (34) 你尝试设置的某个配置项，其值已经是你想要设置的那个值了。
            if (!(result.getExitValue() == 0
                    || result.getExitValue() == 11
                    || result.getExitValue() == 12
                    || result.getExitValue() == 16
                    || result.getExitValue() == 34)) {
                throw new FirewallException(String.format(
                        "Zone: %s, operation port: %s/%s failed, error: %s",
                        zoneName, portRule.getPort(), portRule.getProtocol(), result.outputUTF8()));
            }

            // 如果是永久规则，需要重新加载防火墙
            if (permanent) {
                new ProcessExecutor()
                        .command("/bin/bash", "-c", "firewall-cmd --reload")
                        .timeout(10, TimeUnit.SECONDS)
                        .execute();
            }

            return true;
        } catch (IOException | InterruptedException | TimeoutException e) {
            throw new FirewallException("Failed to execute firewall command: " + e.getMessage(), e);
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

    /**
     * 判断zone是否存在
     * 如果为新增时没有则创建，如果为删除或者查询时没有则报错
     *
     * @param zoneName  需要判断的zone名字
     * @param operation 操作类型
     * @return true表示zone存在或已创建，false表示zone不存在且无法创建
     * @throws FirewallException 当zone不存在且为删除或查询操作时抛出异常
     */
    private boolean ifExistZone(String zoneName, String operation) throws FirewallException {
        try {

            // 获取所有zones
            List<String> zones = new ArrayList<>();
            // sudo firewall-cmd --get-zones
            String commandQueryAllZoneNames = "sudo firewall-cmd --get-zones";
            String zonesStr = WallUtil.execGetLine("sh", "-c", commandQueryAllZoneNames);
            if (zonesStr != null) {
                // 空格
                zones = List.of(zonesStr.split("\\s+"));
            }

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
        } catch (IOException | InterruptedException | TimeoutException e) {
            throw new FirewallException("Failed to check zone existence: " + e.getMessage(), e);
        }
    }


    /**
     * 解析防火墙区域的端口规则，包括普通端口和富规则，封装为 {@link PortRule} 列表。
     * <p>
     * 通过执行以下命令获取对应区域的端口配置信息：
     * <ul>
     *   <li>普通端口列表：<pre>sudo firewall-cmd --zone=zone --list-ports</pre></li>
     *   <li>持久化端口列表：<pre>sudo firewall-cmd --permanent --zone=zone --list-ports</pre></li>
     * </ul>
     * <p>
     * 以及富规则列表：
     * <ul>
     *   <li>普通富规则：<pre>sudo firewall-cmd --zone=zone --list-rich-rules</pre></li>
     *   <li>持久化富规则：<pre>sudo firewall-cmd --permanent --zone=zone --list-rich-rules</pre></li>
     * </ul>
     *
     * <h3>关于端口规则（PortRule）对象映射说明：</h3>
     * <p>
     * 以示例端口 {@code 8086/tcp} 为例：
     * <ul>
     *   <li>family：IPv4 和 IPv6 均会生成一条对应端口规则，表示对这两种协议开放该端口</li>
     *   <li>port：端口号，例如 8086</li>
     *   <li>protocol：协议类型，例如 tcp</li>
     *   <li>sourceRule：来源地址，例如 0.0.0.0，表示对所有来源开放</li>
     *   <li>policy：访问策略，true 表示允许访问，false 表示拒绝</li>
     * </ul>
     * </p>
     *
     * <h3>关于富规则（Rich Rules） {@link PortRule} 对象映射说明：</h3>
     * <p>
     * 以示例规则：
     * <pre>rule family="ipv4" source address="172.16.0.0/24" port port="6456" protocol="tcp" reject</pre>
     * <p>
     * 解析内容：
     * <ul>
     *   <li>family：协议族，例如 ipv4</li>
     *   <li>port：端口号，例如 6456</li>
     *   <li>protocol：协议类型，例如 tcp</li>
     *   <li>sourceRule：来源地址，例如 172.16.0.0/24；若为空，默认视为对所有地址开放</li>
     *   <li>policy：访问策略，false 表示拒绝，true 表示接受</li>
     * </ul>
     * </p>
     *
     * <p>
     * 其他属性（如 agentId、permanent、type、zone）：
     * <ul>
     *   <li>agentId：通过工具类获取</li>
     *   <li>permanent：是否为持久化配置（由命令执行结果的差异判断）</li>
     *   <li>type：规则类型，{@link RuleType#PORT}表示端口规则</li>
     *   <li>zone：区域名，通过参数传入</li>
     * </ul>
     * </p>
     *
     * @param zoneName 防火墙区域名
     * @return 返回封装所有端口规则的 {@link List<PortRule>}
     */
    public List<PortRule> queryAllPortRuleByParseCommand(String zoneName) {

        HashSet<PortRule> portRulesFromListPortCommand = getAllPortFromListPort(zoneName);

        HashSet<PortRule> portRulesFromListRuleRuleCommand = getAllPortFromListRuleRule(zoneName);

        // 涉及到去重，按照PortRule类中定义的规则去重 （含family，port、protocolsourceRule，policy 和父类属性（agentId，permanent，type，zone)）
        portRulesFromListRuleRuleCommand.addAll(portRulesFromListPortCommand);

        return new ArrayList<>(portRulesFromListRuleRuleCommand);
    }

    public HashSet<PortRule> getAllPortFromListRuleRule(String zoneName) {

        HashSet<PortRule> result = new HashSet<>();

        String command1 = "sudo firewall-cmd --zone=" + zoneName + " --list-rich-rules";
        String command2 = "sudo firewall-cmd --permanent --zone=" + zoneName + " --list-rich-rules";
        // 所有的富规则
        String portRules = WallUtil.exec("sh", "-c", command1);
        // 持久化的富规则
        String portRulesWithPermanent = WallUtil.exec("sh", "-c", command2);

        // 表示没有开放的端口
        if (portRules.isEmpty()) {
            return result;
        }

        List<String> portRulesList = List.of(portRules.split("\\r?\\n"));
        List<String> portRulesPermanentList = List.of(portRulesWithPermanent.split("\\r?\\n"));

        String agentId = AgentIdUtil.loadOrCreateUUID();
        for (String ruleStr : portRulesList) {
            List<FirewallRuleParser.ParsedRule> parsedRules = FirewallRuleParser.parseFirewallRule(ruleStr);
            for (FirewallRuleParser.ParsedRule parsedRule : parsedRules) {

                // 获取端口目前是否被使用？
                List<PortInfo> portsInUse = PortMonitorUtils.getPortsInUse(parsedRule.getPort(), parsedRule.getProtocol());
                boolean using = !portsInUse.isEmpty();

                // 该富规则是否是持久化的？
                boolean isPermanent = false;
                if (!portRulesPermanentList.isEmpty()) {
                    isPermanent = portRulesPermanentList.contains(ruleStr);
                }

                PortRule build = PortRule.builder()
                        .descriptor(parsedRule.getDescription())
                        .sourceRule(new SourceRule(parsedRule.getSource()))
                        .policy("accept".equals(parsedRule.getPolicy()))
                        .using(using)
                        .protocol(parsedRule.getProtocol())
                        .port(parsedRule.getPort())
                        .family(parsedRule.getFamily())
                        .build();
                build.setAgentId(agentId);
                build.setPermanent(isPermanent);
                build.setType(RuleType.PORT);
                build.setZone(zoneName);

                result.add(build);

            }
        }


        return result;
    }

    public HashSet<PortRule> getAllPortFromListPort(String zoneName) {

        HashSet<PortRule> result = new HashSet<>();

        String command1 = "sudo firewall-cmd --zone=" + zoneName + " --list-ports";
        String command2 = "sudo firewall-cmd --permanent --zone=" + zoneName + " --list-ports";
        String portsWithProtocols = WallUtil.execGetLine("sh", "-c", command1);
        String portsWithProtocolPermanent = WallUtil.execGetLine("sh", "-c", command2);

        // 表示没有开放的端口
        if (portsWithProtocols == null || portsWithProtocols.isEmpty()) {
            return result;
        }

        // 以空格分隔
        String[] lines = portsWithProtocols.split("\\s+");
        String agentId = AgentIdUtil.loadOrCreateUUID();
        for (String line : lines) {
            line = line.trim();
            // 断言该行包含端口信息，例如：80/tcp 或 8080/tcp
            if (line.matches("^(\\d+(-\\d+)?)/(tcp|udp)$")) {
                String port = line.split("/")[0];
                String protocol = line.split("/")[1];

                // PortRule属性赋值
                RuleType type = RuleType.PORT;
                //是否持久化
                boolean permanent = false;
                // portsWithProtocolPermanent 不为null，表示有持久化开放的端口
                if (portsWithProtocolPermanent != null) {
                    permanent = portsWithProtocolPermanent.contains(line);
                }

                // family
                String family = "ipv4";

                // 如果端口描述为默认值 0.0.0.0，则考虑使用端口监听的进程名字填充
                String descriptor = "0.0.0.0";

                // 端口规则中的状态列含义：
                // 当端口规则中端口为单个端口，比如 (tcp 4567)，using属性为true，表示该机器tcp下该端口正在被使用；为false，表示机器tcp的4567端口未被使用
                // 当端口规则为端口为多个端口，比如 tcp（3456-6543) 或者  udp[23423,553,774]）。using属性为true,表示机器tcp 的 3456-6543范围内有端口被使用了；为false,表示机器tcp 的 3456-6543范围内所有端口都未被占用
                // 具体端口使用详细信息查看PortInfoAdapter类实现
                List<PortInfo> portsInUse = PortMonitorUtils.getPortsInUse(port, protocol);
                boolean using = !portsInUse.isEmpty();
                if (using) {
                    StringBuilder stringBuilder = new StringBuilder();
                    for (PortInfo portInfo : portsInUse) {
                        stringBuilder.append(portInfo.getProcessName()).append(",");
                    }
                    descriptor = stringBuilder.toString();
                }

                boolean policy = true;

                SourceRule sourceRule = new SourceRule("0.0.0.0");

                PortRule build = PortRule.builder()
                        .descriptor(descriptor)
                        .sourceRule(sourceRule)
                        .policy(policy)
                        .using(using)
                        .protocol(protocol)
                        .port(port)
                        .family(family)
                        .build();
                build.setAgentId(agentId);
                build.setPermanent(permanent);
                build.setType(type);
                build.setZone(zoneName);

                PortRule anotherBuild = DeepCopyUtil.deepCopy(build, PortRule.class);
                anotherBuild.setFamily("ipv6");


                result.add(build);
                result.add(anotherBuild);
            }
        }
        return result;
    }

}
