package cn.hedeoer.subscribe;

import cn.hedeoer.util.RedisUtil;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;
import redis.clients.jedis.StreamEntryID;
import redis.clients.jedis.params.XAddParams;

import java.util.HashMap;
import java.util.Map;

public class StreamProducer {
    private final Jedis jedis;
    private final String streamKey;

    public StreamProducer(Jedis jedis, String streamKey) {
        this.jedis = jedis;
        this.streamKey = streamKey;
    }

    /**
     * 向指定的 Redis Stream 发布一条消息，并设置流的最大长度约为 1000 条。
     * <p>
     * 消息以 Map 形式存储到 Redis Stream {@code streamKey} 中；
     * 当消息数超过 1000 条时，Stream 会自动进行近似裁剪（approximate trimming），以限制其最大长度，
     * 有利于节省内存并保持流的活跃状态。
     *
     * @param message 需发布到 Stream 的消息内容，键值对形式
     * @return        新添加消息的 StreamEntryID
     */
    public StreamEntryID publishMessage(Map<String, String> message) {

            // 添加消息并设置Stream最大长度约为1000
            XAddParams params = XAddParams.xAddParams().maxLen(1000).approximateTrimming();
            return jedis.xadd(streamKey, params, message);

    }

    public void close() {
        RedisUtil.close(jedis);
    }

    public static void main(String[] args) {
        Jedis jedis = RedisUtil.getJedis();
        StreamProducer producer = new StreamProducer(jedis, "test1");

        // 发布订单消息示例
        for (int i = 1; i <= 5; i++) {
            Map<String, String> order = new HashMap<>();
            order.put("orderId", String.valueOf(1000 + i));
            order.put("product", "Product-" + i);
            order.put("price", String.valueOf(i * 100));
            order.put("customer", "customer-" + i);

            StreamEntryID messageId = producer.publishMessage(order);
            System.out.println("Published order with ID: " + messageId);
        }

        producer.close();
    }
}
