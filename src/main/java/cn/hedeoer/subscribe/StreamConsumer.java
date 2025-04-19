package cn.hedeoer.subscribe;

import cn.hedeoer.util.RedisUtil;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.StreamEntryID;
import redis.clients.jedis.exceptions.JedisDataException;
import redis.clients.jedis.params.XReadGroupParams;
import redis.clients.jedis.resps.StreamEntry;
import redis.clients.jedis.resps.StreamGroupInfo;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 带有消费者组的 xreadGroup，可阻塞处理
 * XREADGROUP GROUP group consumer [COUNT count] [BLOCK milliseconds] [NOACK] STREAMS key [key ...] id [id ...]
 */
public class StreamConsumer {
    private final Jedis jedis;
    private final String streamKey;
    private final String groupName;
    private final String consumerName;

    public StreamConsumer(Jedis jedis, String streamKey, String groupName, String consumerName) {
        this.jedis = jedis;
        this.streamKey = streamKey;
        this.groupName = groupName;
        this.consumerName = consumerName;

        createConsumerGroupIfNotExists();
    }

    private void createConsumerGroupIfNotExists() {

        // 1. 检查Stream是否存在
        boolean streamExists;
        try {
            jedis.xinfoStream(streamKey);
            streamExists = true;
        } catch (JedisDataException e) {
            if (e.getMessage().contains("no such key")) {
                streamExists = false;
            } else {
                throw e;
            }
        }

        // 2. 如果Stream不存在，先创建Stream（发送一个空消息）
        if (!streamExists) {
//            // 使用自动生成的ID创建初始条目
//            jedis.xadd(streamKey, (StreamEntryID) null, Collections.emptyMap());
//            System.out.println("Stream created: " + streamKey);

            // 创建一个包含单个字段的消息
            Map<String, String> initialEntry = new HashMap<>();
            initialEntry.put("init", "initial");
            jedis.xadd(streamKey, StreamEntryID.NEW_ENTRY, initialEntry);
            System.out.println("Stream created with initial entry: " + streamKey);
        }

        // 3. 检查消费者组是否存在
        boolean groupExists = false;
        try {
            List<StreamGroupInfo> groups = jedis.xinfoGroups(streamKey);
            groupExists = groups.stream()
                    .anyMatch(g -> groupName.equals(g.getName()));
        } catch (JedisDataException e) {
            if (!e.getMessage().contains("NOGROUP")) {
                throw e;
            }
        }

        // 4. 创建组（使用安全的ID参数）
        if (!groupExists) {
            try {
                // 使用0-0从最开始消费，或者使用$从新消息开始消费
                StreamEntryID id = StreamEntryID.MINIMUM_ID; // 或 StreamEntryID.LAST_ENTRY
                jedis.xgroupCreate(streamKey, groupName, id, true);
                System.out.println("Consumer group created: " + groupName);
            } catch (JedisDataException e) {
                if (e.getMessage().contains("BUSYGROUP")) {
                    System.out.println("Consumer group already exists: " + groupName);
                } else if (e.getMessage().contains("Invalid stream ID")) {
                    // 回退方案：尝试使用LAST_ENTRY
                    jedis.xgroupCreate(streamKey, groupName, StreamEntryID.XGROUP_LAST_ENTRY, true);
                    System.out.println("Consumer group created with LAST_ENTRY: " + groupName);
                } else {
                    throw e;
                }
            }
        } else {
            System.out.println("Consumer group already exists: " + groupName);
        }

    }


    /**
     * 以消费者组（Consumer Group）的方式阻塞消费 Redis Stream 中的新消息，并在消费后自动确认（ACK）。
     * <p>
     * 此方法使用 XREADGROUP 命令，从指定的 Stream（由 {@code streamKey} 指定），
     * 针对当前消费者组 ({@code groupName}) 和消费者名称 ({@code consumerName})，
     * 读取尚未被任何消费者处理的新消息（{@code StreamEntryID.XREADGROUP_UNDELIVERED_ENTRY}）。
     * 拉取数不会超过 {@code count}，可阻塞等待新消息到来最长 {@code blockTimeMillis} 毫秒。
     * <p>
     * 方法内会对每条拉取到的消息进行处理（通过简单打印），然后自动调用 XACK 确认消息已处理。
     * 若无新消息，则返回空列表。
     *
     * @param count           最多消费的消息条数
     * @param blockTimeMillis 阻塞等待新消息的最大时间（毫秒），0 表示一直阻塞直到有消息
     * @return                读取并确认的 StreamEntry 消息列表，若无新消息则返回空列表
     */
    public List<StreamEntry> consumeNewMessages(int count, int blockTimeMillis) {

        XReadGroupParams params = XReadGroupParams.xReadGroupParams()
                .count(count)
                .block(blockTimeMillis);

        Map<String, StreamEntryID> streams = Collections.singletonMap(
                streamKey, StreamEntryID.XREADGROUP_UNDELIVERED_ENTRY
        );

        // 使用正确的返回类型
        List<Map.Entry<String, List<StreamEntry>>> response = jedis.xreadGroup(
                groupName, consumerName, params, streams);

        if (response != null && !response.isEmpty()) {
            // 获取第一个流的所有条目（因为我们只查询了一个流）
            List<StreamEntry> entries = response.get(0).getValue();

/*            for (StreamEntry entry : entries) {
                // 处理消息
//                System.out.println("Processing message: " + entry.getID() + " - " + entry.getFields());
                // 确认消息处理完成
                jedis.xack(streamKey, groupName, entry.getID());
            }*/
            return entries;
        }

        return Collections.emptyList();

    }


    public void close() {
        RedisUtil.close(jedis);
    }

    public static void main(String[] args) {
        Jedis jedis = RedisUtil.getJedis();
        StreamConsumer consumer = new StreamConsumer(
                jedis, "test1", "orderConsumers", "consumer1");

        System.out.println("Starting to consume messages...");

        // 消费10轮，每轮最多5条消息，阻塞时间2秒
        for (int i = 0; i < 10; i++) {
            List<StreamEntry> messages = consumer.consumeNewMessages(5, 2000);

            if (messages.isEmpty()) {
                System.out.println("No new messages in round " + (i + 1));
            } else {
                System.out.println("Consumed " + messages.size() + " messages in round " + (i + 1));
            }

            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        consumer.close();
    }
}
