package cn.hedeoer.subscribe.streamadapter;


import cn.hedeoer.common.enmu.FirewallOperationType;
import cn.hedeoer.common.entity.ResponseResult;
import cn.hedeoer.pojo.FirewallStatusInfo;
import cn.hedeoer.subscribe.StreamConsumer;
import cn.hedeoer.subscribe.StreamProducer;
import cn.hedeoer.util.AgentIdUtil;
import cn.hedeoer.util.PingControlUtil;
import cn.hedeoer.util.RedisUtil;
import cn.hedeoer.util.WallUtil;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.StreamEntryID;
import redis.clients.jedis.exceptions.JedisConnectionException;
import redis.clients.jedis.resps.StreamEntry;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 防火墙状态处理适配逻辑
 */
public class FirewallStatusInfoAdapter implements Runnable {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());


    @Override
    public void run() {

        // 获取agent节点的唯一标识
        String agentId = AgentIdUtil.loadOrCreateUUID();
        String subStreamKey = "sub:" + agentId + ":firewallStatusInfo";
        String groupName = "firewall_" + subStreamKey + "_group";
        String consumerName = groupName + "_consumer";
        String pubStreamKey = "pub:" + agentId + ":firewallStatusInfo";

        while (true) {
            try (Jedis jedis = RedisUtil.getJedis()) {
                // 消费流的结果封装
                ResponseResult<List<FirewallStatusInfo>> consumeResult = ResponseResult.success();

                StreamConsumer consumer = new StreamConsumer(jedis, pubStreamKey, groupName, consumerName);

                //本次循环消费消息时最多阻塞1秒
                List<StreamEntry> streamEntries = consumer.consumeNewMessages(1, 4000);
                if (streamEntries.isEmpty()) {
                    continue;
                }
                StreamEntry streamEntry = streamEntries.get(0);

                // 转化 streamEntry的fields为java对象
                FirewallStatusInfoAdapter.FireWallStatusInfoStreamEntry fireWallStatusInfoStreamEntry = fromMap(streamEntry.getFields());

                // 判断此次端口规则操作的类型（PortInfoOpType枚举）
                FirewallOperationType fireWallStatusOpType = judgeFireWallStatusInfoOPType(fireWallStatusInfoStreamEntry);

                logger.info("将进行 {} 操作", fireWallStatusOpType.name());

                List<FirewallStatusInfo> firewallStatusInfos = new ArrayList<>();
                switch (fireWallStatusOpType) {
                    case QUERY:
                        firewallStatusInfos = List.of(WallUtil.getFirewallStatusInfo());
                        break;
                    case RESTART:
                        // 重启防火墙
                        Boolean isRestartDone =  WallUtil.operateFireWall(fireWallStatusOpType);
                        if (!isRestartDone) {
                            consumeResult = ResponseResult.fail(firewallStatusInfos,"重启防火墙失败");
                            break;
                        }
                        break;
                    case START:
                        // 启动防火墙
                        Boolean isStartDone =  WallUtil.operateFireWall(fireWallStatusOpType);
                        if (!isStartDone) {
                            consumeResult = ResponseResult.fail(firewallStatusInfos,"启动防火墙失败");
                            break;
                        }
                        break;
                    case STOP:
                        // 关闭防火墙
                        Boolean isStopDone =  WallUtil.operateFireWall(fireWallStatusOpType);
                        if (!isStopDone) {
                            consumeResult = ResponseResult.fail(firewallStatusInfos,"关闭防火墙失败");
                            break;
                        }
                        break;
                    case BLOCKPING:
                        // 禁止ping
                        Boolean isBlockDone =  PingControlUtil.disablePing();
                        if (!isBlockDone) {
                            consumeResult = ResponseResult.fail(firewallStatusInfos,"禁止外部系统ping失败");
                            break;
                        }
                        break;
                    case UNBLOCKPING:
                        // 启用ping
                        Boolean isUnBlockDone = PingControlUtil.enablePing();
                        if (!isUnBlockDone) {
                            consumeResult = ResponseResult.fail(firewallStatusInfos,"启用外部系统ping失败");
                            break;
                        }
                        break;
                    default:
                        logger.error("不匹配任何规定的防火墙状态操作，{}", fireWallStatusOpType);
                }

                consumeResult.setData(firewallStatusInfos);

                // 确认消息处理完成
                StreamEntryID entryID = streamEntry.getID();

                // 发布数据到 stream key （pub:001:firewallStatusInfo）
                publishMessges(jedis, subStreamKey, entryID, consumeResult);
                jedis.xack(pubStreamKey, groupName, entryID);
                logger.info("agent节点：{} 向 streamKey为：{} 的stream发布 StreamEntryID：{}的消息作为响应成功", agentId, subStreamKey, entryID);

            }
        }
    }

    /**
     * 将map转化为 PortInfoStreamEntry 对象
     * 其中
     * agent_id
     * agent_component_type
     * data_op_type
     * request_params
     * ts
     * 为必填参数，“非空”
     *
     * @param map map
     * @return FireWallStatusInfoStreamEntry
     */
    public static FireWallStatusInfoStreamEntry fromMap(Map<String, String> map) {
        FireWallStatusInfoStreamEntry entry ;
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            // 非空参数
            String agentId = map.get("agentId");
            String agentComponentType = map.get("agentComponentType");
            // 操作类型
            String dataOpType = map.get("dataOpType");
            Map<String, String> requestParams = objectMapper.readValue(map.get("requestParams"), new TypeReference<>() {
            });
            String ts = map.get("ts");

            // 可选参数
            List<String> primaryKeyColumns = new ArrayList<>();
            if (map.containsKey("primaryKeyColumns")) {
                primaryKeyColumns = objectMapper.readValue(map.get("primaryKeyColumns"), new TypeReference<>() {
                });
            }

            // 可选参数
            List<FirewallStatusInfo> data = new ArrayList<>();
            if (map.containsKey("data")) {
                data = objectMapper.readValue(map.get("data"), new TypeReference<>() {
                });
            }

            // 可选参数
            FirewallStatusInfo old = FirewallStatusInfo.builder().build();
            if (map.containsKey("old")) {
                old = objectMapper.readValue(map.get("old"), new TypeReference<>() {
                });
            }


            entry = FireWallStatusInfoStreamEntry.builder()
                    .agentId(agentId)
                    .agentComponentType(agentComponentType)
                    .dataOpType(dataOpType)
                    .requestParams(requestParams)
                    .ts(ts)
                    .primaryKeyColumns(primaryKeyColumns)
                    .data(data)
                    .old(old)
                    .build();
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        return entry;
    }

    @NoArgsConstructor
    @AllArgsConstructor
    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    @Builder
    public static class FireWallStatusInfoStreamEntry {

        private String agentId;

        private String agentComponentType;

        private String dataOpType;

        private Map<String, String> requestParams;

        private String ts;

        private List<String> primaryKeyColumns;

        private List<FirewallStatusInfo> data;

        private FirewallStatusInfo old;
    }



    private FirewallOperationType  judgeFireWallStatusInfoOPType(FireWallStatusInfoStreamEntry fireWallStatusInfoStreamEntry) {
        // 本次操作防火墙状态对应数据操作类型，（query,start，restart,stop）
        String dataOpType = fireWallStatusInfoStreamEntry.getDataOpType();

        FirewallOperationType fireWallStatusOpType = null;
        String agentComponentType = fireWallStatusInfoStreamEntry.getAgentComponentType();

        Map<String, String> requestParams = fireWallStatusInfoStreamEntry.getRequestParams();
        String operation = requestParams.get("operation");

        boolean isQueryFirewallStatusInfo = false;
        boolean isUpdateFirewallByRestart = false;
        boolean isUpdateFirewallByStart = false;
        boolean isUpdateFirewallByStop = false;
        boolean blockPing = false;
        boolean unBlockPing = false;

        if ("firewall".equalsIgnoreCase(agentComponentType)) {

            // 防火墙操作
            isQueryFirewallStatusInfo = "QUERY".equals(dataOpType);

            isUpdateFirewallByRestart = "UPDATE".equals(dataOpType)
                    && operation.equals(FirewallOperationType.RESTART.getValue());

            isUpdateFirewallByStart = "UPDATE".equals(dataOpType)
                    && operation.equals(FirewallOperationType.START.getValue());

            isUpdateFirewallByStop = "UPDATE".equals(dataOpType)
                    && operation.equals(FirewallOperationType.STOP.getValue());

            // 设置是否禁用Ping（禁止外部主机ping本机）
            blockPing = "UPDATE".equals(dataOpType)
                    && operation.equals(FirewallOperationType.BLOCKPING.getValue());

            unBlockPing = "UPDATE".equals(dataOpType)
                    && operation.equals(FirewallOperationType.UNBLOCKPING.getValue());

        }



        // 查询操作
        if (isQueryFirewallStatusInfo) {
            fireWallStatusOpType = FirewallOperationType.QUERY;
        }else if  (isUpdateFirewallByRestart) {
            fireWallStatusOpType = FirewallOperationType.RESTART;
        }else if (isUpdateFirewallByStart){
            fireWallStatusOpType = FirewallOperationType.START;
        }else if (isUpdateFirewallByStop){
            fireWallStatusOpType = FirewallOperationType.STOP;
        }else if(blockPing){
            fireWallStatusOpType = FirewallOperationType.BLOCKPING;
        }else if(unBlockPing){
            fireWallStatusOpType = FirewallOperationType.UNBLOCKPING;
        }else{
            // 什么也不做
        }

        return fireWallStatusOpType;
    }

    private static void publishMessges(Jedis jedis, String streamKey, StreamEntryID entryID, ResponseResult<List<FirewallStatusInfo>> consumeResult) {
        // 检查连接是否有效
        if (!"PONG".equals(jedis.ping())) {
            throw new JedisConnectionException("Redis连接无效");
        }
        //  1.  发布消息时如何指定 entryID 完成，
        //  2. agent向master注册时需要设计agent_Id的生成规则 完成，
        //  3. master的对于agent响应的数据是否需要持久化，需要，比如请求全部的端口规则
        //  master获取 agentId:pub 流数据逻辑 master发布命令后去读取指定的steam即可获取 响应，可以考虑重复读取减少网络波动影响
        //  5. 多参数查询需要支持 isUsing 和policy 完成
        StreamProducer producer = new StreamProducer(jedis, streamKey);
        // 转化为map
        Map<String, String> data = ResponseResult.convertResponseResultToMap(consumeResult);
        // 向streamKey中添加数据，指定entryId为消费master节点时的StreamEntryID
        producer.publishMessage(data, entryID);
        producer.close();
    }


}
