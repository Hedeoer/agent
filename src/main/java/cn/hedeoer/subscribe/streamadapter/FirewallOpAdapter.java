package cn.hedeoer.subscribe.streamadapter;

import cn.hedeoer.subscribe.StreamConsumer;
import cn.hedeoer.util.RedisUtil;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.resps.StreamEntry;

import java.util.List;
import java.util.Map;

/**
 * 对redis stream的 数据做适配响应，比如 当添加或者删除一个防火墙规则时，需要调用方法
 * cn.hedeoer.firewalld.op.PortRuleService#addOrRemoveOnePortRule(java.lang.String, cn.hedeoer.firewalld.PortRule, java.lang.String)
 */
public class FirewallOpAdapter {

    // 获取 redis stream的某个 stream key下的数据，此处的stream key为 agent机器节点的唯一标识
    // 解析 stream 中的数据
    // 判断调用具体的方法

    public static void main(String[] args) {
        Jedis jedis = RedisUtil.getJedis();
        String agentId = "test1";
        String groupName = "firewall_" + agentId + "_group";
        String consumerName = "firewall_" + agentId + "_consumer";
        StreamConsumer consumer = new StreamConsumer(
                jedis, agentId, groupName, consumerName);
        List<StreamEntry> streamEntries = consumer.consumeNewMessages(1, 0);
        StreamEntry streamEntry = streamEntries.get(0);
        Map<String, String> fields = streamEntry.getFields();

    }

}
