package cn.hedeoer.firewall.ufw.op;

import cn.hedeoer.common.enmu.RuleType;
import cn.hedeoer.common.entity.PortRule;
import cn.hedeoer.common.entity.SourceRule;
import cn.hedeoer.firewall.PortRuleService;
import cn.hedeoer.firewall.firewalld.exception.FirewallException;
import cn.hedeoer.firewall.ufw.UfwBackupManager;
import cn.hedeoer.firewall.ufw.UfwRule;
import cn.hedeoer.firewall.ufw.UfwStatus;
import cn.hedeoer.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zeroturnaround.exec.ProcessExecutor;
import org.zeroturnaround.exec.ProcessResult;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;

public class PortRuleServiceImplByUFW implements PortRuleService {
    private static final Logger logger = LoggerFactory.getLogger(PortRuleServiceImplByUFW.class);

    /**
     * 查询ufw管理的所有端口规则，由于ufw中没有zone的概念，默认传入的zone值为public
     *
     * @param zoneName zone名字 固定值 public
     * @return 端口规则的列表
     */
    @Override
    public List<PortRule> queryAllPortRule(String zoneName) {

        List<PortRule> result = new ArrayList<>();
        // 权限检查
        // 执行 sudo ufw status verbose命令
        // 解析命令输出封装为java对象

        boolean isAdmin = PingControlUtil.hasAdminPrivileges();
        if (!isAdmin) {
            return result;
        }

        // 设置超时时间（秒）
        int timeoutSeconds = 10;
        try {

            UfwStatus ufwStatus = getUfwStatus(timeoutSeconds);
            // 封装为List<PortRule>对象
            result = toPortRules(ufwStatus);
            return result;
        } catch (IOException | InterruptedException | TimeoutException e) {
            throw new RuntimeException(e);
        }

    }

    /**
     * 转换使用 sudo ufw status verbose 和 sudo ufw status numbered 两个命令获取ufw的规则
     * @param timeoutSeconds
     * @return
     * @throws IOException
     * @throws InterruptedException
     * @throws TimeoutException
     */
    private  UfwStatus getUfwStatus(int timeoutSeconds) throws IOException, InterruptedException, TimeoutException {
        ProcessResult parseResult1 = new ProcessExecutor()
                .command("sudo", "ufw", "status", "verbose")
                .readOutput(true)
                .timeout(timeoutSeconds, TimeUnit.SECONDS)
                .exitValueNormal() // 确保进程正常退出
                .execute();
        ProcessResult parseResult2 = new ProcessExecutor()
                .command("sudo", "ufw", "status", "numbered")
                .readOutput(true)
                .timeout(timeoutSeconds, TimeUnit.SECONDS)
                .exitValueNormal() // 确保进程正常退出
                .execute();
        String processOut = parseResult1.outputUTF8();
        String numberStr = parseResult2.outputUTF8();

        UfwStatus ufwStatus = UfwStatus.parse(processOut,numberStr);
        return ufwStatus;
    }

    /**
     * 解析UfwStatus，封装为List<PortRule>对象
     * <p>
     * 1.涉及到去重，按照PortRule类中定义的规则去重 （含family，port、protocol sourceRule，policy 和父类属性（agentId，permanent，type，zone））
     * 2. 只考虑入方法的端口规则
     * 3. 策略为 ALLOW, REJECT, DENY
     * 4. 只考虑端口规则
     *
     * @param ufwStatus 解析sudo ufw status verbose输出而来的对象
     * @return List<PortRule>对象
     */
    private List<PortRule> toPortRules(UfwStatus ufwStatus) {

        // 存储最终结果
        List<PortRule> portRules = new ArrayList<>();

        // 去重（PortRule类中定义的规则去重）
        HashSet<PortRule> sets = new HashSet<>();

        List<UfwRule> rules = ufwStatus.getRules();
        if (rules.isEmpty()) {
            return portRules;
        }

        for (UfwRule rule : rules) {

            /**
             * 正则表达式的目的:
             * - 端口范围 (有或无协议):
             * 一个1到5位的数字 (起始端口)
             * 紧跟着一个冒号 :
             * 紧跟着一个1到5位的数字 (结束端口)
             * 可选地，后面可以跟着一个斜杠 / 和一个或多个单词字符 (协议名)。
             * 示例: 1000:2000, 60000:61000/tcp
             * - 单个端口号带协议:
             * 一个1到5位的数字 (端口号)
             * 紧跟着一个斜杠 /
             * 紧跟着一个或多个单词字符 (协议名)。
             * 示例: 80/tcp, 22/udp
             * - 仅单个端口号:
             * 整个字符串就是一个1到5位的数字 (端口号)。
             * 示例: 80, 443
             */
            // 对于非针对端口的规则跳过
            Pattern compile = Pattern.compile("^(?:\\d{1,5}:\\d{1,5}(?:/\\w+)?|\\d{1,5}/\\w+|\\d{1,5})$");
            if (!compile.matcher(rule.getTo()).matches()) {
                continue;
            }

            // 只考虑 IN方向的规则 和 非limit规则
            if ("OUT".equals(rule.getDirection()) || "LIMIT".equals(rule.getAction())) {
                continue;
            }

            // protected String zone;        // 区域名称
            // protected RuleType type;      // 规则类型
            // protected boolean permanent;  // 是否永久规则
            // protected String agentId;    // 所属节点ID
            // private String family;    // ip type (ipv4 ,ipv6)
            // private String port;      // 端口号或范围 (如 "80" 或 "1024:2048")
            // private String protocol;  // 协议 (tcp 或 udp)
            // private Boolean using;    // 端口使用状态 （已使用，未使用）
            // private Boolean policy;   // 端口策略（允许，拒绝）
            // private SourceRule sourceRule; // 源IP地址或CIDR
            // private String descriptor; //端口描述信息

            // ufw没有zone的概念，默认设置public
            String zoneName = "public";

            // 端口规则
            RuleType type = RuleType.PORT;

            // ufw中没有规则的runtime和permanent概念，都是持久化的
            boolean permanent = true;

            // 节点唯一标识
            String agentId = AgentIdUtil.loadOrCreateUUID();

            // 适用ip协议族类型，首先原始规则部分是否有 (v6) 标记，再检查 '源地址' 字段 和 '目标地址' 是否为明确的 IPv6 地址
            String family = rule.isIpv6() ? "ipv6" : "ipv4";

            // 端口 ufw中端口有两种类型（单端口 3453）（区间端口4000:500,统一风格为 4000-500）
            String[] portAndPortocol = rule.getTo().split("/");
            String ruleTo = portAndPortocol[0];
            String port = ruleTo.contains(":") ? ruleTo.replace(":", "-") : ruleTo;

            // 协议 ufw allow 80 如果不指定协议，默认为tcp 和 udp 都适用
            String protocol = portAndPortocol.length == 2 ? portAndPortocol[1] : "tcp/udp";
            boolean isMultiProtocol = "tcp/udp".equals(protocol);

            //端口的使用状态
            boolean using = !PortMonitorUtils.getPortsInUse(port,protocol,family).isEmpty();
//            boolean using = PortMonitorUtils.isPortInUse(port,protocol,family);

            // 该端口规则的策略 ufw中规则的策略有allow,deny,reject,limit
            // allow - 用于需要明确允许的服务和端口
            // deny - 用于安静地拒绝不需要的连接
            // reject - 用于明确通知发送方连接被拒绝（更友好但会泄露更多信息）
            // limit - 用于防止暴力攻击，特别适用于 SSH 等服务
            String action = rule.getAction();
            boolean policy = "ALLOW".equals(action);

            // 源IP地址或CIDR
            // 对于源ip的限制。连续的情况可以使用 IP 网段/子网；UFW 本身不支持在单条规则中指定多个不连续的 IP 地址
            String sourceIps = "Anywhere".equals(rule.getFrom()) ? "0.0.0.0" : rule.getFrom();
            SourceRule sourceRule = new SourceRule(sourceIps);

            // 端口规则的描述 ufw支持对规则做注释, 如果ufw规则没有注释，则设置为""
            String descriptor = rule.getComment() == null ? "" : rule.getComment();

            // 非多协议（tcp/udp）
            if (!isMultiProtocol) {
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

                sets.add(build);
            } else {
                PortRule build = PortRule.builder()
                        .descriptor(descriptor)
                        .sourceRule(sourceRule)
                        .policy(policy)
                        .using(using)
                        .protocol("tcp")
                        .port(port)
                        .family(family)
                        .build();
                build.setAgentId(agentId);
                build.setPermanent(permanent);
                build.setType(type);
                build.setZone(zoneName);

                PortRule anotherBuild = DeepCopyUtil.deepCopy(build, PortRule.class);
                anotherBuild.setProtocol("udp");

                sets.add(build);
                sets.add(anotherBuild);
            }


        }
        // 将set转换为list
        portRules = new ArrayList<>(sets);
        return portRules;
    }

    /**
     * 新增或者删除一条端口规则
     * 删除方式：sudo ufw --force delete <ruleNum>
     * 根据portRule对象获取ufw中对应的规则编号，然后根据编号删除
     *
     *
     * @param zoneName  zone名字
     * @param portRule  端口规则
     * @param operation portRule operation (insert or delete)
     * @return 删除或者新增结果
     * @throws FirewallException firewall异常
     */
    @Override
    public Boolean addOrRemoveOnePortRule(String zoneName, PortRule portRule, String operation) {

        // 判断是删除还是新增
        // 新增
        // 删除

        //sudo ufw allow proto tcp from 192.168.1.0/24 to any port 3000:3100 comment 'Allow TCP traffic to ports 3000-3100 from local network'
        //sudo ufw allow proto tcp from 2001:db8::/64 to any port 8100 comment 'Allow TCP traffic from IPv6 network to web ports'
        //sudo ufw reject proto tcp from 203.0.113.0/24 to any port 22:25 comment 'Reject SSH and mail services from suspicious network'
        //sudo ufw allow proto tcp from 172.16.0.0/16 to any port 1000:2000 comment 'Allow TCP services for internal network'
        //sudo ufw allow proto udp from 172.16.0.0/16 to any port 1000:2000 comment 'Allow UDP services for internal network'

        /**
         * family
         * UFW 会根据 IP 地址的格式自动识别是 IPv4 还是 IPv6 规则
         * ufw中没有指定ipv4还是ipv6，默认就是ipv4和ipv6都可以访问
         * sudo ufw allow proto tcp from 192.168.1.0/24 to any port 3000:3100 comment 'Allow TCP traffic to ports 3000-3100 from local network
         * 该条规则识别为ipv4
         *
         * port
         * ufw中支持范围端口，比如4000:5000
         *
         * protocol
         * ufw中省略表示支持tcp和udp;但是多端口范围必须指定协议
         * sudo ufw allow proto tcp from 2001:db8::/64 to any port 8100:9000 comment 'Allow TCP traffic from IPv6 network to web ports'
         * proto为 tcp
         * sudo ufw allow  from 2001:db8::/64 to any port 8101 comment 'Allow TCP traffic from IPv6 network to web ports8101'
         * proto为 tcp/udp
         *
         * sourceRule
         * ufw中支持ip地址和ip地址段，但是不支持多个不连续的ip地址
         *
         * policy
         * ufw中支持allow,deny,reject,limit此处只考虑 allow，deny，reject; 其中（deny，reject）表示“规则拒绝“，allow表示“规则允许”
         *
         * descriptor
         * ufw中支持对规则进行注释
         */
        try {

            UfwBackupManager.backupUfwConfiguration();

            String family = portRule.getFamily();
            String port = portRule.getPort();
            String protocol = portRule.getProtocol();
            Boolean using = portRule.getUsing();
            Boolean policy = portRule.getPolicy();
            SourceRule sourceRule = portRule.getSourceRule();
            String descriptor = portRule.getDescriptor();
            String agentId = portRule.getAgentId();
            boolean permanent = portRule.isPermanent();
            RuleType type = portRule.getType();
            String zone = portRule.getZone();

            String ruleOP = "";
            if ("delete".equals(operation)) {
                ruleOP = "delete";
            } else if (Boolean.TRUE.equals(policy)) {
                ruleOP = "allow";
            } else if (Boolean.FALSE.equals(policy)) {
                ruleOP = "reject";
            } else {
                return false;
            }


            // 判断是否为多端口？多来源ip限制？
            List<String> multiPorts = List.of(port.split(","));
            boolean isMultiPort = !multiPorts.isEmpty();
            List<String> multiSourceIps = List.of(sourceRule.getSource().split(","));
            boolean isMultiSource = !multiSourceIps.isEmpty();
            List<String> multiProtocols = List.of(protocol.split("/"));
            boolean isMultiProtocol = multiProtocols.isEmpty();

            ArrayList<String> commands = new ArrayList<>();
            String combineCommand = "";
            // 删除规则
                // 新增规则
                for (String currentPort : multiPorts) {
                    // ufw中端口有两种类型（单端口 3453）（前端传递的区间端口4000-5000,统一风格为 4000:5000,符合ufw的格式）
                    currentPort = currentPort.replace("-", ":");
                    for (String currentSourceIp : multiSourceIps) {
                        // 判断ip是否合法
                        boolean validIp = IpUtils.isValidIp(currentSourceIp);
                        if (!validIp) {
                            throw new FirewallException("Invalid IP: " + currentSourceIp);
                        }
                        for (String currentProtocol : multiProtocols) {
                            String command = "";
                            if (!"delete".equals(ruleOP)){
                                // sudo ufw allow proto tcp from 192.168.1.0/24 to any port 3000:3100 comment 'Allow TCP traffic to ports 3000-3100 from local network'
                                command = String.format("sudo ufw %s proto %s from %s to any port %s comment '%s'", ruleOP, currentProtocol, currentSourceIp, currentPort, descriptor);
                            }else{
                                // 通过编号删除
                                Integer ufwRuleNumber = findUfwRuleNumber(portRule);
                                command = String.format("sudo ufw --force delete %s", ufwRuleNumber);
                            }
                            commands.add(command);
                        }
                    }
                }
                combineCommand = String.join(" && ", commands);

            logger.info("Executing firewall command: {}, portRule: {}", combineCommand, portRule);

            // 执行命令

            ProcessResult result = new ProcessExecutor()
                    .command("/bin/bash", "-c", combineCommand)
                    .readOutput(true)
                    .timeout(30, TimeUnit.SECONDS)
                    .execute();

            if (!(result.getExitValue() == 0)) {
                throw new FirewallException(String.format(
                        "Zone: %s, operation port: %s/%s failed, error: %s",
                        zoneName, portRule.getPort(), portRule.getProtocol(), result.outputUTF8()));
            }

            logger.info("Executed firewall command: {} successfully", combineCommand);
            // 删除备份文件
            UfwBackupManager.deleteBackupFiles();
            return true;

        } catch (IOException | TimeoutException | InterruptedException | FirewallException e) {
            // 恢复原来的ufw配置
            UfwBackupManager.restoreUfwConfigurationAndReload();
            UfwBackupManager.deleteBackupFiles();
            throw new RuntimeException(e);
        }
    }


    /**
     * 根据给定的 PortRule 对象，在当前的 UFW (Uncomplicated Firewall) 规则列表中查找匹配的规则，并返回其编号。
     * <p>
     * 此方法会获取当前的 UFW 状态，并逐条比较 UFW 规则与 PortRule 对象的属性，
     * 包括端口、动作（策略）、来源IP、IP版本（IPv4/IPv6）和协议。
     * <p>
     * 注意：
     * <ul>
     *   <li>"LIMIT" 动作的 UFW 规则和 "OUT" 方向的 UFW 规则会被忽略，不参与比较。</li>
     *   <li>UFW 规则中的 "Anywhere" 会被视为 "0.0.0.0" 进行来源比较。</li>
     *   <li>PortRule 中的端口范围（如果使用 "-" 表示）会被转换为 ":" 以匹配 UFW 的端口范围表示。</li>
     *   <li>只有当且仅当找到唯一一条完全匹配的 UFW 规则时，才会返回其编号。
     *       如果找到多条匹配规则或没有找到任何匹配规则，将记录错误并返回 -1。</li>
     * </ul>
     *
     * @param portRule 待匹配的 PortRule 对象，包含了期望的防火墙规则的属性。
     * @return 如果找到唯一匹配的 UFW 规则，则返回其编号 (正整数)；否则返回 -1，表示未找到或找到多个。
     * @throws RuntimeException 如果在获取 UFW 状态或解析规则时发生 IOException、InterruptedException 或 TimeoutException。
     */
    public  Integer findUfwRuleNumber(PortRule portRule) {

        int number = -1;
        // 解析ufw规则
        // 逐次比较ufw规则
        try {
            UfwStatus ufwStatus = getUfwStatus(10);
            List<UfwRule> rules = ufwStatus.getRules();

            // 用于存储符合相等条件的ufw规则
            ArrayList<UfwRule> candidateUfwRules = new ArrayList<>();

            for (UfwRule rule : rules) {
                // 对于limit和out方向的规则，不考虑
                String action = rule.getAction();
                if ("LIMIT".equals(action) || "OUT".equals(rule.getDirection())) {
                    continue;
                }

                String port = portRule.getPort().replace("-",":");
                // 去除字符串中/tcp 或者 /udp前所有内容
                String ruleTo = rule.getTo();
                String portFromUfw = ruleTo.replaceAll("(.*?)/(tcp|udp).*", "$1");
                boolean isPortEqual = port.equals(portFromUfw);
                if (!isPortEqual) {
                    continue;
                }

                String actionFromUfw = "ALLOW".equals(action) ? "allow" : "reject";
                String actionFromPortRule = portRule.getPolicy() ? "allow" : "reject";
                boolean isActionEqual = actionFromUfw.equals(actionFromPortRule);
                if (!isActionEqual) {
                    continue;
                }

                String sourceFromUfw = rule.getFrom().replace("Anywhere", "0.0.0.0");
                boolean isFromEqual = sourceFromUfw.equals(portRule.getSourceRule().getSource());
                if (!isFromEqual) {
                    continue;
                }


//                String commentFromUfw = rule.getComment() == null ? "" : rule.getComment();
//                boolean isCommentEqual = commentFromUfw.equals(portRule.getDescriptor());
//                if (!isCommentEqual) {
//                    continue;
//                }

                boolean isIpv6Equal = rule.isIpv6() == "ipv6".equals(portRule.getFamily());
                if (!isIpv6Equal) {
                    continue;
                }

                String protocolFromUfw = ruleTo.contains("tcp") ? "tcp" : "udp";
                boolean isProtocolEqual = protocolFromUfw.equals(portRule.getProtocol());
                if (!isProtocolEqual) {
                    continue;
                }

                candidateUfwRules.add(rule);


            }

            if (candidateUfwRules.size() != 1) {
                logger.error("When mapping PortRule to UFW rule, Found more than one UFW rules OR not mapping ufw rule, PortRule: {}, UFW rules : {}", portRule,candidateUfwRules);
                return number;
            }
            // 只有当候选规则唯一时，认为匹配成功，才返回规则编号
            number = candidateUfwRules.get(0).getRuleNumber();

        } catch (IOException | InterruptedException | TimeoutException e) {
            throw new RuntimeException(e);
        }
        return number;
    }

    @Override
    public Boolean addOrRemoveBatchPortRules(String zoneName, List<PortRule> portRules, String operation) throws FirewallException {
        boolean result = true;

        // 备份ufw配置
        UfwBackupManager.backupUfwConfiguration();

        for (PortRule portRule : portRules) {
            Boolean currentExec = addOrRemoveOnePortRule(zoneName, portRule, operation);
            if (!currentExec) {
                result =false;
                break;
            }
        }

        // 根据执行结果选择是否恢复ufw配置和删除配置备份文件
        if (!result) {
            UfwBackupManager.restoreUfwConfigurationAndReload();
            UfwBackupManager.deleteBackupFiles();
        }else{
            UfwBackupManager.deleteBackupFiles();
        }

        return result;
    }

    @Override
    public List<PortRule> queryPortRulesByUsingStatus(String zoneName, Boolean isUsing) {
        return List.of();
    }

    @Override
    public List<PortRule> queryPortRulesByPolicy(String zoneName, Boolean policy) {
        return List.of();
    }

    @Override
    public List<PortRule> queryPortRulesByPolicyAndUsingStatus(String zoneName, Boolean isUsing, Boolean policy) {
        return List.of();
    }

    @Override
    public Boolean updateOnePortRule(String zoneName, PortRule oldPortRule, PortRule newPortRule) {

        Boolean result;
        try {

            UfwBackupManager.backupUfwConfiguration();


            // 1. 删除旧的端口规则
            // 2. 添加新的端口规则
            result = addOrRemoveOnePortRule(zoneName, oldPortRule, "delete")
                    && addOrRemoveOnePortRule(zoneName, newPortRule, "insert");

            if (result) {
                UfwBackupManager.deleteBackupFiles();
            }else{
                UfwBackupManager.restoreUfwConfigurationAndReload();
                UfwBackupManager.deleteBackupFiles();
            }

        } catch (Exception e) {
            result =false;
            UfwBackupManager.restoreUfwConfigurationAndReload();
            UfwBackupManager.deleteBackupFiles();
            logger.error(e.getMessage());
        }
        return result;
    }

}
