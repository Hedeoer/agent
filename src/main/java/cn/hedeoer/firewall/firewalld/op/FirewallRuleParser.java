package cn.hedeoer.firewall.firewalld.op;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 解析一条富规则 为 List<ParsedRule>
 */

public class FirewallRuleParser {

    // 类为解析后的规则
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ParsedRule {
        private String port;
        private String protocol;
        private String source;
        private String policy;
        private String description;
        private String family; // 新增 family 属性，默认 family 为 ipv4/ipv6，表示同时规则适用 ipv4 和 ipv6
        private boolean permanent; // 新增 permanent 属性，表示规则是否持久化
    }

    /**
     * 解析防火墙规则字符串
     *
     * @param ruleStr 防火墙规则字符串
     * @return 解析后的规则对象列表
     */
    public static List<ParsedRule> parseFirewallRule(String ruleStr) {
        List<ParsedRule> parsedRules = new ArrayList<>();

        // 提取端口和协议组合
        List<PortProtocol> portProtocols = new ArrayList<>();
        Pattern portPattern = Pattern.compile("port port=\"(\\d+(?:-\\d+)?)\" protocol=\"(\\w+)\"");
        Matcher portMatcher = portPattern.matcher(ruleStr);

        while (portMatcher.find()) {
            portProtocols.add(new PortProtocol(
                    portMatcher.group(1),
                    portMatcher.group(2),
                    portMatcher.start()
            ));
        }

        // 提取源地址
        List<SourceAddress> sourceAddresses = new ArrayList<>();
        Pattern sourcePattern = Pattern.compile("source address=\"([^\"]+)\"");
        Matcher sourceMatcher = sourcePattern.matcher(ruleStr);

        while (sourceMatcher.find()) {
            sourceAddresses.add(new SourceAddress(
                    sourceMatcher.group(1),
                    sourceMatcher.start()
            ));
        }

        // 提取日志前缀（描述）
        List<LogPrefix> logPrefixes = new ArrayList<>();
        Pattern prefixPattern = Pattern.compile("log prefix=\"([^\"]+)\"");
        Matcher prefixMatcher = prefixPattern.matcher(ruleStr);

        while (prefixMatcher.find()) {
            logPrefixes.add(new LogPrefix(
                    prefixMatcher.group(1),
                    prefixMatcher.start()
            ));
        }

        // 提取策略，默认为 null，表示这是一条错误的富规则，无法提取政策信息
        String policy = null;
        if (ruleStr.endsWith("accept")) {
            policy = "accept";
        } else if (ruleStr.endsWith("reject")) {
            policy = "reject";
        } else if (ruleStr.endsWith("drop")) {
            policy = "drop";
        }

        // 提取 family 信息
        String family = null;
        // 是否是同时适用于ipv4和ipv6？
        boolean isMultiFamily = false;
        Pattern familyPattern = Pattern.compile("family=\"(ipv[46])\"");
        Matcher familyMatcher = familyPattern.matcher(ruleStr);
        if (familyMatcher.find()) {
            family = familyMatcher.group(1);
        } else {
            isMultiFamily = true;
        }

        // 提取 permanent 信息，默认值为 false
        boolean permanent = false;
        permanent = ruleStr.contains("--permanent");

        // 对于每个端口 / 协议，查找相关的源地址和描述
        for (PortProtocol pp : portProtocols) {
            // 对于特殊功能策略 mark masquerade forward-port 直接丢弃
            if (policy != null) {
                String source = findApplicableValue(sourceAddresses, pp.position);
                String description = findApplicableValue(logPrefixes, pp.position);

                // 添加所有解析到的信息到 ParsedRule 中
                if (!isMultiFamily) {
                    parsedRules.add(new ParsedRule(pp.port, pp.protocol, source, policy, description, family, permanent));
                }else{
                    // 如果该条富规则同时适用于ivp4和ipv6，则加入两条端口规则
                    parsedRules.add(new ParsedRule(pp.port, pp.protocol, source, policy, description, "ipv4", permanent));
                    parsedRules.add(new ParsedRule(pp.port, pp.protocol, source, policy, description, "ipv6", permanent));
                }
            }
        }

        return parsedRules;
    }

    /**
     * 根据端口位置查找适用的源地址或日志前缀
     *
     * @param values 源地址或日志前缀的列表
     * @param portPosition 端口的位置
     * @return 适用的值
     */
    private static String findApplicableValue(List<? extends PositionedValue> values, int portPosition) {
        if (values.isEmpty()) {
            return "0.0.0.0"; // 默认源地址
        }

        // 查找在端口之前最近定义的值
        PositionedValue result = values.get(0);
        for (PositionedValue value : values) {
            if (value.position < portPosition && value.position > result.position) {
                result = value;
            }
        }

        return result.value;
    }

    // 帮助类：用于跟踪字符串中的位置
    private static abstract class PositionedValue {
        String value;
        int position;

        public PositionedValue(String value, int position) {
            this.value = value;
            this.position = position;
        }
    }

    // 端口和协议的组合类
    private static class PortProtocol extends PositionedValue {
        String port;
        String protocol;

        public PortProtocol(String port, String protocol, int position) {
            super("", position);
            this.port = port;
            this.protocol = protocol;
        }
    }

    // 源地址类
    private static class SourceAddress extends PositionedValue {
        public SourceAddress(String value, int position) {
            super(value, position);
        }
    }

    // 日志前缀类
    private static class LogPrefix extends PositionedValue {
        public LogPrefix(String value, int position) {
            super(value, position);
        }
    }

    public static void main(String[] args) {
        String ruleStr = "rule family=\"ipv4\" " +
                "source address=\"192.168.1.0/24\" " +
                "port port=\"22\" protocol=\"tcp\" " +
                "log prefix=\"SSH Access\" level=\"info\" " +
                "source address=\"10.0.0.0/8\" " +
                "port port=\"80\" protocol=\"tcp\" " +
                "port port=\"443\" protocol=\"tcp\" " +
                "log prefix=\"Web Access\" level=\"notice\" " +
                "accept";

        String ruleStr1 = "rule family=\"ipv4\" source address=\"192.168.1.100\" port port=\"80\" protocol=\"tcp\" log prefix=\"Web Server\" level=\"info\" accept";
        String ruleStr2 = "rule family=\"ipv4\" source address=\"10.0.0.0/24\" port port=\"22\" protocol=\"tcp\" port port=\"443\" protocol=\"tcp\" port port=\"3389\" protocol=\"tcp\" log prefix=\"Remote Access\" level=\"info\" accept";

        String ruleStr3 = "rule family=\"ipv4\" port port=\"53\" protocol=\"udp\" accept";

        String ruleStr4 = "rule family=\"ipv4\" source address=\"172.16.0.0/16\" port port=\"25\" protocol=\"tcp\" log prefix=\"Mail Server\" level=\"warning\" reject";

        String ruleStr5 = "rule family=\"ipv4\" source address=\"192.168.1.0/24\" port port=\"22\" protocol=\"tcp\" log prefix=\"SSH Access\" level=\"info\" source address=\"10.0.0.0/8\" port port=\"80\" protocol=\"tcp\" log prefix=\"Web HTTP\" level=\"notice\" port port=\"443\" protocol=\"tcp\" log prefix=\"Web HTTPS\" level=\"notice\" accept";


        //解析结果：
        //端口号，协议， 源规则，策略， 规则描述
        //53, udp, 192.168.5.0/24, accept, DNS Traffic
        //53, tcp, 192.168.5.0/24, accept, DNS Traffic
        String ruleStr6 = "rule family=\"ipv4\" source address=\"192.168.5.0/24\" port port=\"53\" protocol=\"udp\" port port=\"53\" protocol=\"tcp\" log prefix=\"DNS Traffic\" level=\"info\" accept";

        String ruleStr7 = "rule family=\"ipv4\" source address=\"10.10.10.0/24\" port port=\"8080\" protocol=\"tcp\" port port=\"9000\" protocol=\"tcp\" accept";
        String ruleStr8 = "rule family=\"ipv4\" source address=\"203.0.113.0/24\" port port=\"1234\" protocol=\"tcp\" log prefix=\"Blocked Traffic\" level=\"warning\" drop";


        String ruleStr9 = "rule family=\"ipv6\" source address=\"2001:db8::/64\" port port=\"80\" protocol=\"tcp\" log prefix=\"IPv6 Web\" level=\"info\" accept";

        String ruleStr10 = "rule \" source address=\"2001:db8::/64\" port port=\"80\" protocol=\"tcp\" log prefix=\"IPv6 Web\" level=\"info\" accept";

        String ruleStr11 = "rule family=\"ipv4\" source address=\"172.16.10.11\" port port=\"8234-8235\" protocol=\"tcp\" reject";

        List<ParsedRule> rules = parseFirewallRule(ruleStr11);
        
        System.out.println("解析结果：");
        System.out.println("端口号，协议， 源规则，策略， 规则描述");
        for (ParsedRule rule : rules) {
            System.out.println(rule);
        }
    }
}
