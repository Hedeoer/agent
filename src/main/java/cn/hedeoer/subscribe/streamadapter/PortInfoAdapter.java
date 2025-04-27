package cn.hedeoer.subscribe.streamadapter;

import cn.hedeoer.common.ResponseResult;
import cn.hedeoer.firewalld.PortRule;
import cn.hedeoer.pojo.PortInfo;
import cn.hedeoer.subscribe.StreamConsumer;
import cn.hedeoer.subscribe.StreamProducer;
import cn.hedeoer.util.AgentIdUtil;
import cn.hedeoer.util.PortMonitorUtils;
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
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.StreamEntryID;
import redis.clients.jedis.resps.StreamEntry;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class PortInfoAdapter implements Runnable {

    private static final Logger logger = LoggerFactory.getLogger(PortInfoAdapter.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void run() {

        // 获取agent节点的唯一标识
        String agentId = AgentIdUtil.loadOrCreateUUID();
        String subStreamKey = "sub:" + agentId + ":portInfo";
        String groupName = "firewall_" + subStreamKey + "_group";
        String consumerName = groupName + "_consumer";
        String pubStreamKey = "pub:" + agentId + ":portInfo";

//            SimpleStreamConsumer simpleStreamConsumer = new SimpleStreamConsumer(jedis, subStreamKey);

        // 消费流的结果封装
        ResponseResult<List<PortInfo>> consumeResult = ResponseResult.success();
        while (true) {
            try (Jedis jedis = RedisUtil.getJedis()) {

                StreamConsumer consumer = new StreamConsumer(jedis, pubStreamKey, groupName, consumerName);

                //本次循环消费消息时最多阻塞1秒
                List<StreamEntry> streamEntries = consumer.consumeNewMessages(1, 0);
                if (streamEntries.isEmpty()) {
//                    logger.info("streamKey:{}, 目前无新消息",pubStreamKey);
                    continue;
                }
                StreamEntry streamEntry = streamEntries.get(0);

                // 转化 streamEntry的fields为java对象
                PortInfoStreamEntry portInfoStreamEntry = fromMap(streamEntry.getFields());

                // 判断此次端口规则操作的类型（PortInfoOpType枚举）
                PortInfoOpType portRuleOpType = judgePortInfoOpType(portInfoStreamEntry);

                Map<String, String> requestParams = portInfoStreamEntry.getRequestParams();
                // 防火墙zone
                String zoneName = requestParams.get("zoneName");
                String dataOpType = portInfoStreamEntry.getDataOpType();
                List<PortInfo> datas = portInfoStreamEntry.getData();

                logger.info("将进行 {} 操作", portRuleOpType.name());

                List<PortInfo> portInfos = null;
                switch (portRuleOpType) {
                    case QUERY_PARTTIAL_PORTINFO:
                        portInfos = PortMonitorUtils.getPortsUsage(new ArrayList<String>());
                        if (portInfos == null) {
                            consumeResult = ResponseResult.fail(portInfos, "无法获取端口相关的占用信息！！");
                            break;
                        }
                        break;
                    default:
                        logger.error("不匹配任何规定的端口规则操作，{}", portRuleOpType);
                }
                consumeResult.setData(portInfos);

                // 确认消息处理完成
                StreamEntryID entryID = streamEntry.getID();

                // 发布数据到 stream key （pub:001:portInfo）
                StreamEntryID streamEntryID = publishMessges(jedis, subStreamKey, entryID, consumeResult);
                jedis.xack(pubStreamKey, groupName, entryID);
                logger.info("agent节点：{} 向 streamKey为：{} 的stream发布 StreamEntryID：{}的消息作为响应成功", agentId, subStreamKey, entryID);

            }catch (RuntimeException e) {
                logger.error("消费过程出错", e);
                // 可选休眠再重试，避免疯循环
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ignored) {
                }
            }
        }
    }

    private PortInfoOpType judgePortInfoOpType(PortInfoStreamEntry portInfoStreamEntry) {
        // 该节点的某个资源类型，比如防火墙资源（cn.hedeoer.pojo.FireWallType.UFW 或者 cn.hedeoer.pojo.FireWallType.FIREWALLD）
        String agentComponentType = portInfoStreamEntry.getAgentComponentType();

        // 本次操作防火墙端口规则对应数据操作类型，（insert ， delete，update，query）
        String dataOpType = portInfoStreamEntry.getDataOpType();

        // 本次端口规则操作前的数据，只有操作类型为update时，才会有oldData
        PortInfo oldData = portInfoStreamEntry.getOld();

        // 本次端口规则操作后需要达到的目标数据（只有操作类型为insert或者delete时，才会有data ）
        List<PortInfo> data = portInfoStreamEntry.getData();

        // 本次端口规则操作的需要的请求参数，只有query时，才会有值
        // queryAllPortInfo(String zoneName) /agent_id=?&&zoneName=?
        // queryPortInfosByUsingStatus(String zoneName, Boolean isUsing) /agent_id=?&&zoneName=?&&isUsing=?
        // queryPortInfosByPolicy(String zoneName, Boolean policy) /agent_id=?&&zoneName=?&&policy=?
        Map<String, String> requestParams = portInfoStreamEntry.getRequestParams();

        PortInfoOpType portInfoOpType = null;
        // 查询操作
        if ("QUERY_PARTTIAL".equals(dataOpType)) {
            portInfoOpType = PortInfoOpType.QUERY_PARTTIAL_PORTINFO;
        }

        return portInfoOpType;
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
     * @param map
     * @return
     */
    public static PortInfoStreamEntry fromMap(Map<String, String> map) {
        PortInfoStreamEntry entry = null;
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            // 非空参数
            String agentId = map.get("agentId");
            String agentComponentType = map.get("agentComponentType");
            // 操作类型
            String dataOpType = map.get("dataOpType");
            Map<String, String> requestParams = objectMapper.readValue(map.get("requestParams"), new TypeReference<Map<String, String>>() {
            });
            String ts = map.get("ts");

            // 可选参数
            List<String> primaryKeyColumns = new ArrayList<String>();
            if (map.containsKey("primaryKeyColumns")) {
                primaryKeyColumns = objectMapper.readValue(map.get("primaryKeyColumns"), new TypeReference<List<String>>() {
                });
            }

            // 可选参数
            List<PortInfo> data = new ArrayList<PortInfo>();
            if (map.containsKey("data")) {
                data = objectMapper.readValue(map.get("data"), new TypeReference<List<PortInfo>>() {
                });
            }

            // 可选参数
            PortInfo old = new PortInfo();
            if (map.containsKey("old")) {
                old = objectMapper.readValue(map.get("old"), new TypeReference<PortInfo>() {
                });
            }


            entry = PortInfoStreamEntry.builder()
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

    private static StreamEntryID publishMessges(Jedis jedis, String streamKey, StreamEntryID entryID, ResponseResult<List<PortInfo>> consumeResult) {
        //  1.  发布消息时如何指定 entryID 完成，
        //  2. agent向master注册时需要设计agent_Id的生成规则 完成，
        //  3. master的对于agent响应的数据是否需要持久化，需要，比如请求全部的端口规则
        //  todo 4. master获取 agentId:pub 流数据逻辑 master发布命令后去读取指定的steam即可获取 响应，可以考虑重复读取减少网络波动影响
        //  5. 多参数查询需要支持 isUsing 和policy 完成
        StreamProducer producer = new StreamProducer(jedis, streamKey);
        // 转化为map
        Map<String, String> data = ResponseResult.convertResponseResultToMap(consumeResult);
        // 向streamKey中添加数据，指定entryId为消费master节点时的StreamEntryID
        StreamEntryID streamEntryID = producer.publishMessage(data, entryID);
        producer.close();
        return streamEntryID;
    }


    @NoArgsConstructor
    @AllArgsConstructor
    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    @Builder
    public static class PortInfoStreamEntry {

        private String agentId;

        private String agentComponentType;

        private String dataOpType;

        private Map<String, String> requestParams;

        private String ts;

        private List<String> primaryKeyColumns;

        private List<PortInfo> data;

        private PortInfo old;
    }

    /**
     * 端口规则操作类型
     */
    private enum PortInfoOpType {
        QUERY_ALL_PORTINFO,
        QUERY_PARTTIAL_PORTINFO,
        OPTIONS;
    }


}
