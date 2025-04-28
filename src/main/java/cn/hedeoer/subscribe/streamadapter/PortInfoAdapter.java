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
import com.fasterxml.jackson.databind.JsonMappingException;
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

        while (true) {
            try (Jedis jedis = RedisUtil.getJedis()) {
                // 消费流的结果封装
                ResponseResult<List<PortInfo>> consumeResult = ResponseResult.success();

                StreamConsumer consumer = new StreamConsumer(jedis, pubStreamKey, groupName, consumerName);

                //本次循环消费消息时最多阻塞1秒
                List<StreamEntry> streamEntries = consumer.consumeNewMessages(1, 0);
                if (streamEntries.isEmpty()) {
                    continue;
                }
                StreamEntry streamEntry = streamEntries.get(0);

                // 转化 streamEntry的fields为java对象
                PortInfoStreamEntry portInfoStreamEntry = fromMap(streamEntry.getFields());

                // 判断此次端口规则操作的类型（PortInfoOpType枚举）
                PortInfoOpType portRuleOpType = judgePortInfoOpType(portInfoStreamEntry);

                Map<String, String> requestParams = portInfoStreamEntry.getRequestParams();

                logger.info("将进行 {} 操作", portRuleOpType.name());

                List<PortInfo> portInfos = null;
                switch (portRuleOpType) {
                    case QUERY_PARTTIAL_PORTINFO:

                        if (!requestParams.isEmpty()) {
                            // 端口区间类型1：ONEPORT 比如 4343
                            // 端口区间类型1 RANGE_PORT_DASH 比如 40000-50000
                            // 端口区间类型1 RANGE_PORT_COMMA 比如 3467,12245,562
                            String portType = requestParams.get("portType");
                            String port = requestParams.get("port");

                            switch (portType) {
                                case "RANGE_PORT_DASH":
                                    String[] split = port.split("-");
                                    portInfos = PortMonitorUtils.getPortsUsage(split[0],split[1]);
                                    break;
                                case "RANGE_PORT_COMMA":
                                    List<String> portList = objectMapper.readValue(port, new TypeReference<List<String>>() {
                                    });
                                    portInfos = PortMonitorUtils.getPortsUsage(portList);
                                    break;
                                case "ONEPORT":
                                    portInfos = PortMonitorUtils.getPortUsage(port);
                                    break;
                                default:
                                    logger.error("端口类型不匹配定义的任何形式（RANGE_PORT_COMMA，RANGE_PORT_DASH，RANGE_PORT_COMMA）");
                            }
                        }
                        if (portInfos == null) {
                            consumeResult = ResponseResult.fail(null, "无法获取端口相关的占用信息！！");
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
                publishMessges(jedis, subStreamKey, entryID, consumeResult);
                jedis.xack(pubStreamKey, groupName, entryID);
                logger.info("agent节点：{} 向 streamKey为：{} 的stream发布 StreamEntryID：{}的消息作为响应成功", agentId, subStreamKey, entryID);

            } catch (JsonMappingException e) {
                throw new RuntimeException(e);
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private PortInfoOpType judgePortInfoOpType(PortInfoStreamEntry portInfoStreamEntry) {
        // 本次操作防火墙端口规则对应数据操作类型，（insert ， delete，update，query）
        String dataOpType = portInfoStreamEntry.getDataOpType();
        String agentComponentType = portInfoStreamEntry.getAgentComponentType();

        boolean isQueryPartialPortInfo = "QUERY".equals(dataOpType)
                && "PORT".equals(agentComponentType);



        PortInfoOpType portInfoOpType = null;
        // 查询操作
        if (isQueryPartialPortInfo) {
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
     * @param map map
     * @return PortInfoStreamEntry
     */
    public static PortInfoStreamEntry fromMap(Map<String, String> map) {
        PortInfoStreamEntry entry ;
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
            List<PortInfo> data = new ArrayList<>();
            if (map.containsKey("data")) {
                data = objectMapper.readValue(map.get("data"), new TypeReference<>() {
                });
            }

            // 可选参数
            PortInfo old = PortInfo.builder().build();
            if (map.containsKey("old")) {
                old = objectMapper.readValue(map.get("old"), new TypeReference<>() {
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

    private static void publishMessges(Jedis jedis, String streamKey, StreamEntryID entryID, ResponseResult<List<PortInfo>> consumeResult) {
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
        OPTIONS
    }


}
