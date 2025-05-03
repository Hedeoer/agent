package cn.hedeoer.firewalld.ufw.op;

import cn.hedeoer.common.entity.PortRule;
import cn.hedeoer.firewalld.PortRuleService;
import org.junit.Before;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

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
        portRules.forEach(System.out::println);
    }
}