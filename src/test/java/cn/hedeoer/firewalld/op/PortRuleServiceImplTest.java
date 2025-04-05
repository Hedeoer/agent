package cn.hedeoer.firewalld.op;

import cn.hedeoer.firewalld.PortRule;
import cn.hedeoer.firewalld.SourceRule;
import cn.hedeoer.firewalld.exception.FirewallException;
import org.junit.Test;

import java.util.List;

public class PortRuleServiceImplTest {


    @Test
    public void queryAllPortRule() {
        PortRuleServiceImpl service = new PortRuleServiceImpl();
        List<PortRule> list = service.queryAllPortRule("public");
        for (PortRule port : list) {
            System.out.println(port);
        }
    }

    @Test
    public void addOrRemovePortRule() throws FirewallException {
        PortRuleServiceImpl service = new PortRuleServiceImpl();
        SourceRule sourceRule = new SourceRule("172.16.0.0/24,172.16.10.11");
        PortRule portRule = PortRule.builder()
                .protocol("tcp")
                .port("30001")
                .sourceRule(sourceRule)
                .policy(true)
                .descriptor("add port")
                .build();
        System.out.println(service.addOrRemovePortRule("public", portRule,"delete"));
    }
}