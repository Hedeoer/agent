package cn.hedeoer.agent;

import cn.hedeoer.util.AgentIdUtil;
import cn.hedeoer.util.RedisUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;

import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

/**
 * agent节点的心跳检测
 */
public class HeartBeat implements Runnable{
    private final String heartBeatHashTableName = "heartbeats";
    private static final Logger logger = LoggerFactory.getLogger(HeartBeat.class);


    /**
     * 心跳检测方法
     */
    @Override
    public void run() {

        // agent节点的心跳汇报
        // 向master注册(通过使用 redis hash方式， hash表名字 heartbeats, key为agentId, vaule为向master节点上报时的时间戳)
        // 获取redis服务器本地时间戳，避免一旦集群里服务器时间不同步，心跳状态的判断就容易出错
        // 周期性执行hset命令，向master节点汇报心跳，比如 30秒

        try (Jedis jedis = RedisUtil.getJedis()) {
            // 执行 TIME 命令
            List<String> timeResult = jedis.time();
            String seconds = timeResult.get(0);      // 秒级时间戳（字符串格式，需转换）
            String microseconds = timeResult.get(1); // 微秒部分

            String agentId = AgentIdUtil.loadOrCreateUUID();
            //If the field already exists, and the HSET just produced an update of the value, 0 is
            // returned, otherwise if a new field is created 1 is returned.
            long hset = jedis.hset(heartBeatHashTableName, agentId, seconds);

            // 心跳汇报 1745164416_0： 1745164416表示向master节点汇报时的时间戳，0表示非首次汇报，1表示首次汇报
            long judgeFirstBeatFlag = jedis.hset(heartBeatHashTableName, agentId, seconds + "_" + hset);

            logger.info("agentId：{} 向 master节点发送心跳，是否首次: {}",agentId, hset == 1);
        }

    }
}
