package cn.hedeoer.firewall.ufw;

import org.junit.Test;

public class UfwRuleTest {

    @Test
    public void parseFromStatus() {
/*        String rule99  = "[17] 8103                       ALLOW IN    2001:db8::/64              # Allow TCP traffic from IPv6 network to web ports8101";
//        String rule99  = "[ 2] 53                         ALLOW OUT   Anywhere                   (out)";
        UfwRule ufwRule = UfwRule.parseFromStatus(rule99);
        System.out.println("ufwRule = " + ufwRule);
        System.out.println("ufwRule.getRuleNumber() = " + ufwRule.getRuleNumber());
        System.out.println("ufwRule.getFrom() = " + ufwRule.getFrom());
        System.out.println("ufwRule.getTo() = " + ufwRule.getTo());
        System.out.println("ufwRule.getAction() = " + ufwRule.getAction());
        System.out.println("ufwRule.getDirection() = " + ufwRule.getDirection());
        System.out.println("ufwRule.getComment() = " + ufwRule.getComment());
        System.out.println("ufwRule.isIpv6() = " + ufwRule.isIpv6());*/



        String[] testRules = {
                "[ 1] 22/tcp                     ALLOW IN    Anywhere                   # SSH",
                "[ 2] 53                         ALLOW OUT   Anywhere                   (out)", // 测试 (out)
                "80/tcp                     ALLOW IN    Anywhere                   (v6)", // 无编号，有 (v6)
                "[ 4] 443                        DENY IN     192.168.1.100",
                "[ 5] 1000:2000/udp              REJECT IN   Anywhere",
                "[ 6] Anywhere                   LIMIT IN    Anywhere                   [disabled] # Rate limit all",
                "[ 7] 25/tcp                     ALLOW OUT   Anywhere",
                "[ 8] 2001:db8::100              ALLOW IN    2001:db8::/64              # IPv6 specific",
                "[ 9] 8080                       ALLOW IN    Anywhere                   (v6) # Web App",
                "[10] 22                         ALLOW IN    10.0.0.5",
                "[11] 3000                       ALLOW IN    192.168.0.0/16 (v6)", // To, From, v6 in From
                "[12] 3000:3100/tcp              ALLOW IN    Anywhere (v6)",
                "[13] 22 (v6)                    ALLOW IN    Anywhere (v6)", // To has v6, From has v6
                "[14] 22/tcp                     ALLOW IN    Anywhere ( ইন )", // 测试孟加拉语 (in)
                "[15] 5000                       ALLOW IN    Anywhere (out)             # Misplaced (out) but testing robustness",
                "[16] 9000                       ALLOWIN     Anywhere                   # Combined ActionDirection",
                "[17] 8103                       ALLOW IN    2001:db8::/64              # Allow TCP traffic from IPv6 network to web ports8101",
                "Default: deny (incoming), allow (outgoing), disabled (routed)" // Should be skipped
        };

        System.out.println("解析结果:");
        for (String ruleLine : testRules) {
            UfwRule rule = UfwRule.parseFromStatus(ruleLine);
            if (rule != null) {
                System.out.println("原始: " + ruleLine);
                System.out.println("解析: " + rule);
                System.out.println("---");
            } else {
                System.out.println("原始: " + ruleLine + " -> 解析失败或跳过");
                System.out.println("---");
            }
        }

        System.out.println("\n测试特定规则：");
        String rule1  = "[17] 8103                       ALLOW IN    2001:db8::/64              # Allow TCP traffic from IPv6 network to web ports8101";
        String rule2  = "[ 2] 53                         ALLOW OUT   Anywhere                   (out)";
        UfwRule parsedRule1 = UfwRule.parseFromStatus(rule1);
        UfwRule parsedRule2 = UfwRule.parseFromStatus(rule2);
        System.out.println("Rule 1: " + (parsedRule1 != null ? parsedRule1.toString() : "解析失败"));
        System.out.println("Rule 2: " + (parsedRule2 != null ? parsedRule2.toString() : "解析失败"));
        if(parsedRule2 != null){
            System.out.println("Rule 2 From: " + parsedRule2.getFrom() + ", Direction: " + parsedRule2.getDirection() + ", isIPv6: " + parsedRule2.isIpv6());
        }
    }
}