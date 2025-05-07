package cn.hedeoer.firewall.ufw.op;

import cn.hedeoer.common.enmu.RuleType;
import cn.hedeoer.common.entity.PortRule;
import cn.hedeoer.common.entity.SourceRule;
import cn.hedeoer.firewall.PortRuleService;
import cn.hedeoer.firewall.firewalld.exception.FirewallException;
import cn.hedeoer.firewall.ufw.UfwRule;
import cn.hedeoer.firewall.ufw.UfwRuleConverterWithYourParser;
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

public class PortRuleServiceImplByUFW implements PortRuleService {
    private static final Logger logger = LoggerFactory.getLogger(PortRuleServiceImplByUFW.class);

    /**
     * 构造方法，初始化时将ufw规则转换为详细格式供后续使用
     */
    public PortRuleServiceImplByUFW(){
        covertUfwRuleToDetailStyle();
    }

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
            ProcessResult parseResult1 = new ProcessExecutor()
                    .command("sudo", "ufw", "status", "verbose")
                    .readOutput(true)
                    .timeout(timeoutSeconds, java.util.concurrent.TimeUnit.SECONDS)
                    .exitValueNormal() // 确保进程正常退出
                    .execute();
            ProcessResult parseResult2 = new ProcessExecutor()
                    .command("sudo", "ufw", "status", "numbered")
                    .readOutput(true)
                    .timeout(timeoutSeconds, java.util.concurrent.TimeUnit.SECONDS)
                    .exitValueNormal() // 确保进程正常退出
                    .execute();
            String processOut = parseResult1.outputUTF8();
            String numberStr = parseResult2.outputUTF8();

            UfwStatus ufwStatus = UfwStatus.parse(processOut,numberStr);

            // 封装为List<PortRule>对象
            result = toPortRules(ufwStatus);
            return result;
        } catch (IOException | InterruptedException | TimeoutException e) {
            throw new RuntimeException(e);
        }

    }

    /**
     * 解析UfwStatus，封装为List<PortRule>对象
     * <p>
     * 1.涉及到去重，按照PortRule类中定义的规则去重 （含family，port、protocol sourceRule，policy 和父类属性（agentId，permanent，type，zone））
     * 2. 只考虑入方法的端口规则
     * 3.
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
            boolean using = PortMonitorUtils.isPortInUse(port);

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

            // 端口规则的描述 ufw支持对规则做注释
            String descriptor = rule.getComment();

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
                                // sudo ufw delete allow proto tcp from 192.168.1.0/24 to any port 3000:3100
                                // 增加delete关键字，移除规则注释
                                // todo 端口删除方案需要优化？使用编号删除还是 使用原来命令删除？
                                // sudo ufw allow 22/tcp
                                //sudo ufw allow 22/udp
                                String originalRuleOP = policy ? "allow" : "reject";
                                command = String.format("sudo ufw delete %s proto %s from %s to any port %s", originalRuleOP, currentProtocol, currentSourceIp, currentPort);
                            }
                            commands.add(command);
                        }
                    }
                }
                combineCommand = String.join(" && ", commands);

            logger.info("Executing firewall command: {}", combineCommand);

            // 执行命令

            ProcessResult result = new ProcessExecutor()
                    .command("/bin/bash", "-c", combineCommand)
                    .readOutput(true)
                    .timeout(30, TimeUnit.SECONDS)
                    .execute();

            // todo 状态码可能需要更改为ufw的
            if (!(result.getExitValue() == 0
                    || result.getExitValue() == 11
                    || result.getExitValue() == 12
                    || result.getExitValue() == 16
                    || result.getExitValue() == 34)) {
                throw new FirewallException(String.format(
                        "Zone: %s, operation port: %s/%s failed, error: %s",
                        zoneName, portRule.getPort(), portRule.getProtocol(), result.outputUTF8()));
            }

            logger.info("Executed firewall command: {} successfully", combineCommand);

            return true;

        } catch (IOException | TimeoutException | InterruptedException | FirewallException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Boolean addOrRemoveBatchPortRules(String zoneName, List<PortRule> portRules, String operation) throws FirewallException {
        return null;
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
    public Boolean updateOnePortRule(String zoneName, PortRule oldPortRule, PortRule newPortRule) throws FirewallException {
        return null;
    }



    /**
     * 将通用的 UFW "IN" 方向规则（例如 "22 ALLOW IN Anywhere # SSH"）
     * 转换为更具体的 TCP 和 UDP 规则，并保留原始注释。
     * 此方法会从规则号最大的规则开始处理，以正确处理动态变化的规则序号。
     *
     * @throws IOException          如果命令执行期间发生 I/O 错误。
     * @throws InterruptedException 如果当前线程在等待命令完成时被中断。
     * @throws TimeoutException     如果命令执行超时。
     */
    public static Boolean covertUfwRuleToDetailStyle(){

        try {
            UfwRuleConverterWithYourParser.covertUfwRuleToDetailStyle();
        } catch (IOException | InterruptedException | TimeoutException e) {
            throw new RuntimeException(e);
        }

        return true;
    }

}
