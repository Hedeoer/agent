package cn.hedeoer.firewalld.ufw.op;

import cn.hedeoer.common.enmu.RuleType;
import cn.hedeoer.common.entity.PortRule;
import cn.hedeoer.common.entity.SourceRule;
import cn.hedeoer.firewalld.PortRuleService;
import cn.hedeoer.firewalld.firewalld.exception.FirewallException;
import cn.hedeoer.firewalld.ufw.UfwRule;
import cn.hedeoer.firewalld.ufw.UfwStatus;
import cn.hedeoer.util.AgentIdUtil;
import cn.hedeoer.util.PingControlUtil;
import cn.hedeoer.util.PortMonitorUtils;
import org.zeroturnaround.exec.ProcessExecutor;
import org.zeroturnaround.exec.ProcessResult;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeoutException;

public class PortRuleServiceImplByUFW implements PortRuleService {
    /**
     * 查询ufw管理的所有端口规则，由于ufw中没有zone的概念，默认传入的zone值为public
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
            ProcessResult parseResult = new ProcessExecutor()
                    .command("sudo", "ufw", "status", "verbose")
                    .readOutput(true)
                    .timeout(timeoutSeconds, java.util.concurrent.TimeUnit.SECONDS)
                    .exitValueNormal() // 确保进程正常退出
                    .execute();
            String processOut = parseResult.outputUTF8();

            UfwStatus ufwStatus = UfwStatus.parse(processOut);

            // 封装为List<PortRule>对象
            result =  toPortRules(ufwStatus);
            return result;
        } catch (IOException | InterruptedException | TimeoutException e) {
            throw new RuntimeException(e);
        }

    }

    /**
     * 解析UfwStatus，封装为List<PortRule>对象
     * @param ufwStatus 解析sudo ufw status verbose输出而来的对象
     * @return List<PortRule>对象
     */
    private List<PortRule> toPortRules(UfwStatus ufwStatus) {

        List<PortRule> portRules = new ArrayList<>();

        List<UfwRule> rules = ufwStatus.getRules();
        if (rules.isEmpty()) {
            return portRules;
        }

        for (UfwRule rule : rules) {

            // 只考虑 IN方向的规则
            if ("OUT".equals(rule.getDirection())) {
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

            // ip类型，通过端口来判断 或者 通过解析ufw status verbose中是否包含 v6字样
            String family = rule.isIpv6() ? "ipv6" : "ipv4";

            // 端口 ufw中端口有两种类型（单端口 3453）（区间端口4000:500,统一风格为 4000-500）
            String[] portAndPortocol = rule.getTo().split("/");
            String ruleTo = portAndPortocol[0];
            String port = ruleTo.contains(":") ? ruleTo.replace(":", "-") : ruleTo;

            // 协议 ufw allow 80 如果不指定协议，默认为tcp
            String protocol = portAndPortocol.length == 2 ? portAndPortocol[1] : "tcp";

            //端口的使用状态
            boolean using = PortMonitorUtils.isPortInUse(port);

            // 该端口规则的策略 ufw中规则的策略有allow,deny,reject,limit
            // allow - 用于需要明确允许的服务和端口
            // deny - 用于安静地拒绝不需要的连接
            // reject - 用于明确通知发送方连接被拒绝（更友好但会泄露更多信息）
            // limit - 用于防止暴力攻击，特别适用于 SSH 等服务
            String action = rule.getAction();
            boolean policy = "ALLOW".equals(action) || "LIMIT".equals(action);

            // 源IP地址或CIDR
            // 对于源ip的限制。连续的情况可以使用 IP 网段/子网；UFW 本身不支持在单条规则中指定多个不连续的 IP 地址
            String sourceIps = "Anywhere".equals(rule.getFrom()) ? "0.0.0.0" : rule.getFrom();
            SourceRule sourceRule = new SourceRule(sourceIps);

            // 端口规则的描述 ufw支持对规则做注释
            String descriptor = rule.getComment();

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

            portRules.add(build);
        }
        return portRules;
    }

    @Override
    public Boolean addOrRemoveOnePortRule(String zoneName, PortRule portRule, String operation) throws FirewallException {
        return null;
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
}
