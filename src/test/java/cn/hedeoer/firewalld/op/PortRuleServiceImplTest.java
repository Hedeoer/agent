package cn.hedeoer.firewalld.op;

import cn.hedeoer.common.entity.PortRule;
import cn.hedeoer.common.entity.SourceRule;
import cn.hedeoer.firewall.firewalld.exception.FirewallException;
import cn.hedeoer.common.enmu.FireWallType;
import cn.hedeoer.firewall.firewalld.op.PortRuleServiceImplByFirewalld;
import cn.hedeoer.util.DeepCopyUtil;
import cn.hedeoer.util.WallUtil;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

public class PortRuleServiceImplTest {




    @Test
    public void queryAllPortRule() {
        PortRuleServiceImplByFirewalld service = new PortRuleServiceImplByFirewalld();
        List<PortRule> list = service.queryAllPortRule("public");
        for (PortRule port : list) {
            System.out.println(port);
        }
    }

    @Test
    public void addOrRemovePortRule() throws FirewallException {
        PortRuleServiceImplByFirewalld service = new PortRuleServiceImplByFirewalld();
        SourceRule sourceRule = new SourceRule("172.16.0.0/24,172.16.10.11");
        PortRule portRule = PortRule.builder()
                .protocol("tcp")
                .port("30001")
                .sourceRule(sourceRule)
                .policy(true)
                .descriptor("add port")
                .build();
        System.out.println(service.addOrRemoveOnePortRule("public", portRule,"insert"));
    }

    @Test
    public void addOrRemovePortRuleByMultiProtocol() throws FirewallException {

        //  rich rules:
        //        rule family="ipv4" source address="192.168.1.20" service name="ssh" accept limit value="3/m"
        //        rule family="ipv4" port port="8080" protocol="tcp" reject
        //        rule family="ipv4" source address="192.168.1.0/24" port port="22" protocol="tcp" log prefix="SSH Access" level="info" accept
        //        rule family="ipv4" source address="10.0.0.0/8" port port="80" protocol="tcp" log prefix="Web HTTP" level="notice" accept
        //        rule family="ipv4" source address="10.0.0.0/8" port port="443" protocol="tcp" log prefix="Web HTTPS" level="notice" accept


        SourceRule sourceRule2 = new SourceRule("10.0.0.0/8");
        PortRule portRule2 = PortRule.builder()
                .protocol("tcp/udp")
                .port("5555")
                .sourceRule(sourceRule2)
                .policy(true)
                .descriptor("Web HTTP")
                .build();

        PortRuleServiceImplByFirewalld service = new PortRuleServiceImplByFirewalld();
        System.out.println(service.addOrRemoveOnePortRule("public", portRule2, "delete"));
    }

    @Test
    public void testAddOrRemovePortRuleByMultiPort() throws FirewallException {
        SourceRule sourceRule = new SourceRule("172.16.0.99");
        PortRule portRule = PortRule.builder()
                .protocol("udp")
                .port("6666,5555")
                .sourceRule(sourceRule)
                .policy(true)
                .descriptor("add port")
                .build();
        PortRuleServiceImplByFirewalld service = new PortRuleServiceImplByFirewalld();
        System.out.println(service.addOrRemoveOnePortRule("public", portRule, "delete"));
    }

    @Test
    public void testAddOrRemovePortRuleByMultiPortAndMultiProtocol() throws FirewallException {
        SourceRule sourceRule = new SourceRule("182.16.0.99");
        PortRule portRule = PortRule.builder()
                .protocol("udp/tcp")
                .port("6666,5555")
                .sourceRule(sourceRule)
                .policy(false)
                .descriptor("add port")
                .build();
        PortRuleServiceImplByFirewalld service = new PortRuleServiceImplByFirewalld();
        System.out.println(service.addOrRemoveOnePortRule("public", portRule, "delete"));
    }


    @Test
    public void addOrRemoveBatchPortRules() throws FirewallException {
        List<PortRule> rules = new ArrayList<>();
        SourceRule sourceRule = new SourceRule("172.16.0.0/24,172.16.10.11");
        PortRule portRule = PortRule.builder()
                .protocol("tcp")
                .port("30001")
                .sourceRule(sourceRule)
                .policy(true)
                .descriptor("add port")
                .build();
        rules.add(portRule);

        SourceRule sourceRule1 = new SourceRule("192.168.1.20");
        PortRule portRule1 = PortRule.builder()
                .protocol("tcp")
                .port("30001")
                .sourceRule(sourceRule1)
                .policy(true)
                .descriptor("add port")
                .build();
        rules.add(portRule1);

        SourceRule sourceRule2 = new SourceRule("10.0.0.0/8");
        PortRule portRule2 = PortRule.builder()
                .protocol("tcp/udp")
                .port("5555")
                .sourceRule(sourceRule2)
                .policy(true)
                .descriptor("Web HTTP")
                .build();
        rules.add(portRule2);

        PortRuleServiceImplByFirewalld service = new PortRuleServiceImplByFirewalld();
        Boolean aBoolean = service.addOrRemoveBatchPortRules("public", rules, "delete");
        System.out.println(aBoolean);
        if (aBoolean){
            WallUtil.reloadFirewall(FireWallType.FIREWALLD);
        }
    }

    @Test
    public void queryPortRulesByUsingStatus() {
        PortRuleServiceImplByFirewalld service = new PortRuleServiceImplByFirewalld();

        List<PortRule> rules = service.queryPortRulesByUsingStatus("public", Boolean.FALSE);
        rules.forEach(System.out::println);
    }

    @Test
    public void updateOnePortRule() throws FirewallException {
        PortRuleServiceImplByFirewalld service = new PortRuleServiceImplByFirewalld();
        SourceRule sourceRule = new SourceRule("172.16.0.0/24,172.16.10.11");
        PortRule portRule = PortRule.builder()
                .protocol("tcp")
                .port("30001")
                .sourceRule(sourceRule)
                .policy(true)
                .descriptor("add port")
                .build();
        Boolean aBoolean = service.addOrRemoveOnePortRule("public", portRule, "insert");
        WallUtil.reloadFirewall(FireWallType.FIREWALLD);

        PortRule newPortRule = DeepCopyUtil.deepCopy(portRule, PortRule.class);
        newPortRule.setProtocol("udp");
        Boolean aBoolean1 = service.updateOnePortRule("public", portRule, newPortRule);
        System.out.println("update ： " + aBoolean1);
        if (aBoolean1) {
            WallUtil.reloadFirewall(FireWallType.FIREWALLD);
        }

    }

    @Test
    public void queryPortRulesByPolicy() {
        PortRuleServiceImplByFirewalld service = new PortRuleServiceImplByFirewalld();

        List<PortRule> rules = service.queryPortRulesByPolicy("public", Boolean.TRUE);
        rules.forEach(System.out::println);
    }

    @Test
    public void queryPortRulesByPolicyAndUsingStatus() {
        PortRuleServiceImplByFirewalld service = new PortRuleServiceImplByFirewalld();

        List<PortRule> rules = service.queryPortRulesByPolicyAndUsingStatus("public", null,null );
        rules.forEach(System.out::println);
    }
}