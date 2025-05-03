package cn.hedeoer.subscribe.streamadapter;

import cn.hedeoer.common.entity.PortRule;
import org.junit.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class FirewallOpAdapterTest {

    @Test
    public void fromMap() throws IOException {
        Map<String, String> dataMap = new HashMap<>();
        // 添加键值对
        dataMap.put("agent_id", "test");
        dataMap.put("agent_component_type", "firewall");
        dataMap.put("data_op_type", "insert");
//        dataMap.put("request_params", "{\"isUsing\":\"false\",\"policy\":\"true\"}");
        dataMap.put("request_params", "{\"isUsing\":false,\"policy\":true}");
        dataMap.put("ts", "1477053217");
        dataMap.put("primary_key_columns", "[\"port\",\"protocol\"]");
        dataMap.put("data", "[{\"zone\":\"public\",\"type\":\"PORT\",\"permanent\":true,\"family\":\"ipv4\",\"port\":\"6379\",\"protocol\":\"tcp\",\"using\":true,\"policy\":true,\"sourceRule\":{\"source\":\"All IPs allowed\"},\"descriptor\":\"All IPs allowed\"}]");
        dataMap.put("old", "{\"zone\":\"public\",\"type\":\"PORT\",\"permanent\":true,\"family\":\"ipv4\",\"port\":\"6379\",\"protocol\":\"tcp\",\"using\":true,\"policy\":false,\"sourceRule\":{\"source\":\"All IPs allowed\"},\"descriptor\":\"All IPs allowed\"}");

        FirewallOpAdapter adapter = new FirewallOpAdapter();
        FirewallOpAdapter.PortRuleStreamEntry portRuleStreamEntry = adapter.fromMap(dataMap);
        System.out.println(portRuleStreamEntry);

    }

    @Test
    public void testFromMap() {
        Map<String, String> dataMap = new HashMap<>();
        dataMap.put("agent_id", "test");
        dataMap.put("agent_component_type", "firewall");
        dataMap.put("data_op_type", "insert");
        dataMap.put("request_params", "{\"isUsing\":false,\"policy\":true}");
        dataMap.put("ts", "1477053217");

        // 包含嵌套 source_rule 的数据
        String data = "[{\"zone\":\"public\",\"permanent\":true,\"family\":\"ipv4\"," +
                "\"port\":\"8088\",\"protocol\":\"tcp\",\"using\":false,\"policy\":true," +
                "\"sourceRule\":{\"source\":\"172.16.10.11,172.16.0.0/24\"},\"descriptor\":\"\"}]";
        dataMap.put("data", data);

        FirewallOpAdapter.PortRuleStreamEntry entry = FirewallOpAdapter.fromMap(dataMap);

        // 验证嵌套对象是否正确反序列化
        assertNotNull(entry.getData());
        assertEquals(1, entry.getData().size());

        PortRule portRule = entry.getData().get(0);
        assertNotNull(portRule.getSourceRule());
        assertEquals("172.16.10.11,172.16.0.0/24", portRule.getSourceRule().getSource());
    }
}