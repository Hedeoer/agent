package cn.hedeoer.firewalld.ufw.op;

import cn.hedeoer.common.entity.PortRule;
import cn.hedeoer.common.entity.SourceRule;
import cn.hedeoer.firewall.PortRuleService;
import cn.hedeoer.firewall.ufw.op.PortRuleServiceImplByUFW;
import org.junit.Before;
import org.junit.Test;

import java.util.List;
import java.util.regex.Pattern;

public class PortRuleServiceImplByUFWTest {

    PortRuleService portRuleService;

    @Before
    public void init(){
        portRuleService = new PortRuleServiceImplByUFW();
    }

    @Test
    public void queryAllPortRule() {
        /**
         * Status: active
         * Logging: on (low)
         * Default: deny (incoming), allow (outgoing), disabled (routed)
         * New profiles: skip
         *
         * To	Action	From	Comment
         * 22	ALLOW IN	Anywhere
         * 80/tcp	ALLOW IN	Anywhere	# 允许HTTP入站
         * 443/tcp	REJECT IN	192.168.1.100	# 拒绝特定IP访问HTTPS
         * 22/tcp	LIMIT IN	Anywhere	# 限制SSH入站速率
         * 4567	ALLOW IN	Anywhere
         * 22	(v6) ALLOW	IN
         * 80/tcp	(v6) ALLOW	IN	# 允许HTTP入站
         * 22/tcp	(v6) LIMIT	IN	# 限制SSH入站速率
         * 4567	(v6) ALLOW	IN
         * 53/udp	DENY OUT	Anywhere	# 拒绝DNS出站
         * 53/udp	(v6) DENY	OUT	# 拒绝DNS出站
         */
        List<PortRule> portRules = portRuleService.queryAllPortRule("public");
        System.out.println(portRules.size());
        portRules.forEach(System.out::println);
    }

    @Test
    public void findUfwRuleNumber() {
        PortRule portRule1 = PortRule.builder()
                .protocol("tcp")
                .port("30001")
                .sourceRule(new SourceRule("172.16.0.0/24,172.16.10.11"))
                .policy(true)
                .descriptor("add port")
                .family("ipv4")
                .build();

        PortRule portRule2 = PortRule.builder()
                .protocol("tcp")
                .port("587")
                .sourceRule(new SourceRule("0.0.0.0"))
                .policy(true)
                .descriptor("(out) # Allow SMTP out generic")
                .family("ipv4")
                .build();

        PortRule portRule3 = PortRule.builder()
                .protocol("tcp")
                .port("22")
                .sourceRule(new SourceRule("2001:db8:abcd:12::1"))
                .policy(true)
                .descriptor("# Allow SSH from specific IPv6 host")
                .family("ipv6")
                .build();

        PortRule portRule4 = PortRule.builder()
                .protocol("tcp")
                .port("50000")
                .sourceRule(new SourceRule("0.0.0.0"))
                .policy(true)
                .descriptor("")
                .family("ipv4")
                .build();

        PortRuleServiceImplByUFW impl = new PortRuleServiceImplByUFW();
        System.out.println(impl.findUfwRuleNumber(portRule4));
    }

    @Test
    public void findUfwRule() {
        String rule = "7834/tcp";
        String rule1 = "7834:8000/tcp";
        String rule2 = "7834/udp";
        String rule3 = "7834";
        Pattern compile = Pattern.compile("^(?:\\d{1,5}:\\d{1,5}(?:/\\w+)?|\\d{1,5}/\\w+|\\d{1,5})$");
        if (!compile.matcher(rule1).matches()) {
            System.out.println("不匹配");
        }else{
            System.out.println("匹配");
        }
    }
}