package cn.hedeoer.subscribe;

import cn.hedeoer.util.RedisUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
    private static final Logger logger = LoggerFactory.getLogger(StreamConsumer.class);

    public StreamConsumer(Jedis jedis, String streamKey, String groupName, String consumerName) {
        this.jedis = jedis;
        this.streamKey = streamKey;
        this.groupName = groupName;
        this.consumerName = consumerName;

        createConsumerGroupIfNotExists();
    }


    private void createConsumerGroupIfNotExists() {
        // 1. 检查 Stream 是否存在
        boolean streamExists = true;
        try {
            jedis.xinfoStream(streamKey);
        } catch (JedisDataException e) {
            if (e.getMessage() != null && e.getMessage().contains("no such key")) {
                streamExists = false;
            } else {
                throw e;
            }
        }

        // 2. 如果 Stream 不存在，创建一个空的 Stream
        if (!streamExists) {
            try {
                // 使用 XGROUP CREATE 命令的 MKSTREAM 选项创建空流
                jedis.xgroupCreate(streamKey, groupName, null, true);
                logger.info("Stream created without initial data: {}", streamKey);
            } catch (Exception e) {
                // 如果消费者组已存在，只需创建流
                if (e.getMessage().contains("BUSYGROUP")) {
                    // 直接创建空流 (在新版 Jedis 中)
                    jedis.xadd(streamKey, StreamEntryID.NEW_ENTRY, new HashMap<>());
                    logger.info("Stream already exists, consumer group already created: {}", streamKey);
                } else {
                    throw e;
                }
            }
        }


        // 3. 检查消费者组是否存在
        boolean groupExists = false;
        try {
            List<StreamGroupInfo> groups = jedis.xinfoGroups(streamKey);
            groupExists = groups.stream().anyMatch(g -> groupName.equals(g.getName()));
        } catch (JedisDataException e) {
            if (!e.getMessage().contains("NOGROUP")) {
                throw e;
            }
        }

        // 4. 创建消费者组，如果不存在
        if (!groupExists) {
            try {
                jedis.xgroupCreate(streamKey, groupName, StreamEntryID.XGROUP_LAST_ENTRY, true);
                logger.info("Consumer group created from latest ($): {}", groupName);
            } catch (JedisDataException e) {
                String msg = e.getMessage();
                if (msg != null && msg.contains("BUSYGROUP")) {
                    logger.info("Consumer group already exists: {}", groupName);
                } else {
                    throw e;
                }
            }
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
            return entries;
        }

        return Collections.emptyList();

    }


    public void close() {
        RedisUtil.close(jedis);
    }
}
