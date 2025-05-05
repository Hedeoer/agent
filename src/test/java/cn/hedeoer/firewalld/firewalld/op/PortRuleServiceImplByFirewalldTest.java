package cn.hedeoer.firewalld.firewalld.op;

import cn.hedeoer.common.entity.PortRule;
import cn.hedeoer.util.WallUtil;
import com.google.gson.stream.JsonToken;
import org.junit.Test;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import static org.junit.Assert.*;

public class PortRuleServiceImplByFirewalldTest {

    @Test
    public void getAllPortFromListPort() {
        PortRuleServiceImplByFirewalld ob = new PortRuleServiceImplByFirewalld();
        HashSet<PortRule> aPublic = ob.getAllPortFromListPort("public");
        aPublic.forEach(System.out::println);
    }

    @Test
    public void getAllPortFromListRuleRule() {
        PortRuleServiceImplByFirewalld ob = new PortRuleServiceImplByFirewalld();
        HashSet<PortRule> aPublic = ob.getAllPortFromListRuleRule("public");
        for (PortRule portRule : aPublic) {
            System.out.println(portRule);
        }
    }

    @Test
    public void testZoneExists(){
        // 获取所有zones
        List<String> zones = new ArrayList<>();
        // sudo firewall-cmd --get-zones
        String commandQueryAllZoneNames = "sudo firewall-cmd --get-zones";
        String zonesStr = WallUtil.execGetLine("sh", "-c", commandQueryAllZoneNames);
        if (zonesStr !=null) {
            zones = List.of(zonesStr.split("\\s+"));
        }
        System.out.println(zones.size());
        for (String zone : zones) {
            System.out.println(zone);
        }
    }

    @Test
    public void queryAllPortRule() {
        PortRuleServiceImplByFirewalld ob = new PortRuleServiceImplByFirewalld();
        List<PortRule> aPublic = ob.queryAllPortRule("public");
        System.out.println(aPublic.size());
        aPublic.forEach(System.out::println);
    }
}