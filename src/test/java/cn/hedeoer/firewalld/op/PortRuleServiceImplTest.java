package cn.hedeoer.firewalld.op;

import cn.hedeoer.firewalld.PortRule;
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
}