package cn.hedeoer.firewalld.op;

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

    // Class to represent a parsed rule
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ParsedRule {
        private String port;
        private String protocol;
        private String source;
        private String policy;
        private String description;

    }

    public static List<ParsedRule> parseFirewallRule(String ruleStr) {
        List<ParsedRule> parsedRules = new ArrayList<>();

        // Extract all port and protocol combinations
        List<PortProtocol> portProtocols = new ArrayList<>();
        Pattern portPattern = Pattern.compile("port port=\"(\\d+)\" protocol=\"(\\w+)\"");
        Matcher portMatcher = portPattern.matcher(ruleStr);
        
        while (portMatcher.find()) {
            portProtocols.add(new PortProtocol(
                portMatcher.group(1),
                portMatcher.group(2),
                portMatcher.start()
            ));
        }

        // Extract all source addresses
        List<SourceAddress> sourceAddresses = new ArrayList<>();
        Pattern sourcePattern = Pattern.compile("source address=\"([^\"]+)\"");
        Matcher sourceMatcher = sourcePattern.matcher(ruleStr);
        
        while (sourceMatcher.find()) {
            sourceAddresses.add(new SourceAddress(
                sourceMatcher.group(1),
                sourceMatcher.start()
            ));
        }

        // Extract all log prefixes (descriptions)
        List<LogPrefix> logPrefixes = new ArrayList<>();
        Pattern prefixPattern = Pattern.compile("log prefix=\"([^\"]+)\"");
        Matcher prefixMatcher = prefixPattern.matcher(ruleStr);
        
        while (prefixMatcher.find()) {
            logPrefixes.add(new LogPrefix(
                prefixMatcher.group(1),
                prefixMatcher.start()
            ));
        }

        // Extract policy，默认为null，表示这是一条错误的富规则，无法提取policy
        String policy = null;
        if (ruleStr.endsWith("accept")) {
            policy = "accept";
        } else if (ruleStr.endsWith("reject")) {
            policy = "reject";
        } else if (ruleStr.endsWith("drop")) {
            policy = "drop";
        }

        // For each port/protocol, find the relevant source and description
        for (PortProtocol pp : portProtocols) {
            // 对于特殊功能策略 mark masquerade forward-port 直接丢弃
            if (policy != null) {
                String source = findApplicableValue(sourceAddresses, pp.position);
                String description = findApplicableValue(logPrefixes, pp.position);

                parsedRules.add(new ParsedRule(pp.port, pp.protocol, source, policy, description));
            }
        }

        return parsedRules;
    }

    // Find the source or log prefix that applies to a port by looking at positions
    private static String findApplicableValue(List<? extends PositionedValue> values, int portPosition) {
        if (values.isEmpty()) {
            return "All IPs allowed"; // Default for source
        }
        
        // Find the most recently defined value before the port
        PositionedValue result = values.get(0);
        for (PositionedValue value : values) {
            if (value.position < portPosition && value.position > result.position) {
                result = value;
            }
        }
        
        return result.value;
    }

    // Helper classes to keep track of positions in the string
    private static abstract class PositionedValue {
        String value;
        int position;
        
        public PositionedValue(String value, int position) {
            this.value = value;
            this.position = position;
        }
    }
    
    private static class PortProtocol extends PositionedValue {
        String port;
        String protocol;
        
        public PortProtocol(String port, String protocol, int position) {
            super("", position);
            this.port = port;
            this.protocol = protocol;
        }
    }
    
    private static class SourceAddress extends PositionedValue {
        public SourceAddress(String value, int position) {
            super(value, position);
        }
    }
    
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


        List<ParsedRule> rules = parseFirewallRule(ruleStr9);
        
        System.out.println("解析结果：");
        System.out.println("端口号，协议， 源规则，策略， 规则描述");
        for (ParsedRule rule : rules) {
            System.out.println(rule);
        }
    }
}
