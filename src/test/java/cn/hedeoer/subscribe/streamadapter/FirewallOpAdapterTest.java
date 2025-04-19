package cn.hedeoer.subscribe.streamadapter;

import org.junit.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
}