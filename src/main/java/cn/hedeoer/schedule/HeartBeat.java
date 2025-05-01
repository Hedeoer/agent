package cn.hedeoer.schedule;

import cn.hedeoer.common.OSType;
import cn.hedeoer.util.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;

/**
 * agent节点的心跳检测
 */
public class HeartBeat implements Runnable{
    private final String heartBeatHashTableName = "firewall:heartbeats";
    private static final Logger logger = LoggerFactory.getLogger(HeartBeat.class);
    private final ObjectMapper objectMapper = new ObjectMapper();
    private Integer heartBeatGap;

    public  HeartBeat(){}

    public  HeartBeat(Integer heartBeatGap){
        this.heartBeatGap = heartBeatGap;
    }


    /**
     * 心跳检测方法
     */
    @Override
    public void run() {

        // agent节点的心跳汇报
        // 向master注册(通过使用 redis hash方式， hash表名字 firewall:heartbeats, key为agentId, vaule为向master节点上报时的时间戳)
        // 获取redis服务器本地时间戳，避免一旦集群里服务器时间不同步，心跳状态的判断就容易出错
        // 周期性执行hset命令，向master节点汇报心跳，比如 30秒
        sendHearBeat();

    }

    public boolean sendHearBeat() {
        try (Jedis jedis = RedisUtil.getJedis()) {
            boolean res = false;
            String agentId = AgentIdUtil.loadOrCreateUUID();

            String agentNodeInfoSerializeStr  = getNeedReportInfo(jedis,agentId);
            // 心跳汇报 1745164416_0： 1745164416表示向master节点汇报时的时间戳，0表示非首次汇报，1表示首次汇报
            long hset = jedis.hset(heartBeatHashTableName, agentId, agentNodeInfoSerializeStr);
            if (hset == 0 || hset == 1) {
                res = true;
            }else{
                logger.error("agentId：{} 向 master节点发送心跳失败，当前配置心跳时间间隔 : {} 秒",agentId, this.heartBeatGap);
            }

            return res;
        }
    }

    /**
     * 获取需要汇报的信息，并使用jackson序列化为字符串
     * @param jedis jedis
     * @param agentId agent唯一标识
     * @return 如果序列化失败返回null
     */
    private String getNeedReportInfo(Jedis jedis, String agentId)  {


        // 执行 TIME 命令
        String seconds = RedisUtil.getRedisServerTime();      // 秒级时间戳（字符串格式，需转换）

        // 是否首次上报
        boolean isFirstHeartBeat = jedis.hget(heartBeatHashTableName, agentId) == null;

        OSType osType = OperateSystemUtil.getOSType(null);
        String osName = osType.getName();

        // hostName
        String hostName = OperateSystemUtil.getHostName();

        String ip = IpUtils.getLocalIpAddress();
        AgentNodeInfo build = AgentNodeInfo.builder()
                .agentId(agentId)
                .heartbeatTimestamp(seconds)
                .isFirstHeartbeat(isFirstHeartBeat)
                // 上报存活
                .isActive(true)
                .osName(osName)
                .hostName(hostName)
                .ip(ip)
                .clientVersion(VersionHelper.getVersion())
                .cpuUsage(OperateSystemUtil.getCpuUsage())
                .memoryUsage(OperateSystemUtil.getMemoryUsage())
                .diskUsage(OperateSystemUtil.getAvgDiskUsage())
                .build();

        String result = null;
        try {
            result = objectMapper.writeValueAsString(build);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }


        return result;
    }

    /**
     * agent节点向master节点汇报心跳时，需要汇报的信息
     * 上报心跳时间戳，是否首次上报， 是否存活，操作系统，主机名，节点ip
     *
     */
    //   /** CPU利用率 */
    //  cpuUsage?: number
    //  /** 内存利用率 */
    //  memoryUsage?: number
    //  /** 磁盘利用率 */
    //  diskUsage?: number
    //  /** 客户端版本 */
    //  clientVersion?: string
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class AgentNodeInfo {
        private String agentId;
        private String heartbeatTimestamp;
        private Boolean isFirstHeartbeat;
        private Boolean isActive;
        private String osName;
        private String hostName;
        private String ip;
        private String cpuUsage;
        private String memoryUsage;
        private String diskUsage;
        private String clientVersion;
    }
}
