package cn.hedeoer.subscribe;

import cn.hedeoer.util.RedisUtil;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPoolConfig;
import redis.clients.jedis.StreamEntryID;
import redis.clients.jedis.params.XReadParams;
import redis.clients.jedis.resps.StreamEntry;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * 没有消费者的 xread，可阻塞读取
 * XREAD [COUNT count] [BLOCK milliseconds] STREAMS key [key ...] ID [ID ...]
 */
public class SimpleStreamConsumer {
    private final Jedis jedis;
    private final String streamKey;
    private StreamEntryID lastSeenId;

    public SimpleStreamConsumer(Jedis jedis, String streamKey) {
        this.jedis = jedis;
        this.streamKey = streamKey;
        this.lastSeenId = StreamEntryID.XGROUP_LAST_ENTRY; // 从最新的开始
    }

    public List<StreamEntry> readNewMessages(int count, int blockTimeMillis) {

        XReadParams params = XReadParams.xReadParams()
                .count(count)
                .block(blockTimeMillis);

        Map<String, StreamEntryID> streams = Collections.singletonMap(
                streamKey, lastSeenId != null ? lastSeenId : StreamEntryID.XGROUP_LAST_ENTRY
        );

        // 使用正确的返回类型处理
        List<Map.Entry<String, List<StreamEntry>>> response = jedis.xread(params, streams);

        if (response != null && !response.isEmpty()) {
            // 获取第一个流的结果（因为我们只查询了一个流）
            List<StreamEntry> entries = response.get(0).getValue();

            if (!entries.isEmpty()) {
                // 更新最后看到的ID，下次从这里继续
                lastSeenId = entries.get(entries.size() - 1).getID();
            }
            return entries;
        }

        return Collections.emptyList();

    }


    public void close() {
        RedisUtil.close(jedis);
    }

    public static void main(String[] args) {
        Jedis jedis = RedisUtil.getJedis();
        SimpleStreamConsumer consumer = new SimpleStreamConsumer(
                jedis, "orders");

        System.out.println("Starting simple consumer...");

        // 尝试读取新消息5次
        for (int i = 0; i < 5; i++) {
            List<StreamEntry> messages = consumer.readNewMessages(10, 3000);

            if (messages.isEmpty()) {
                System.out.println("No new messages in attempt " + (i + 1));
            } else {
                System.out.println("Read " + messages.size() + " messages:");
                for (StreamEntry entry : messages) {
                    System.out.println("  " + entry.getID() + ": " + entry.getFields());
                }
            }

            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        consumer.close();
    }
}
