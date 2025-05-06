package cn.hedeoer.firewall.ufw;

import org.junit.Test;

import static org.junit.Assert.*;

public class UfwRuleTest {

    @Test
    public void parseFromStatus() {
        String rule  = "8102/tcp                   ALLOW IN    2001:db8::/64              # Explicitly IPv6 rule";
        UfwRule ufwRule = UfwRule.parseFromStatus(rule);
        System.out.println(ufwRule.isIpv6());
    }
}