package cn.hedeoer.subscribe.streamadapter;

import cn.hedeoer.common.ResponseResult;
import cn.hedeoer.common.ResponseStatus;
import cn.hedeoer.firewalld.PortRule;
import cn.hedeoer.firewalld.exception.FirewallException;
import cn.hedeoer.firewalld.op.PortRuleServiceImpl;
import cn.hedeoer.pojo.FireWallType;
import cn.hedeoer.subscribe.SimpleStreamConsumer;
import cn.hedeoer.subscribe.StreamConsumer;
import cn.hedeoer.subscribe.StreamProducer;
import cn.hedeoer.util.AgentIdUtil;
import cn.hedeoer.util.RedisUtil;
import cn.hedeoer.util.WallUtil;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
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
import redis.clients.jedis.resps.StreamEntry;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 对redis stream的 数据做适配响应，比如 当添加或者删除一个防火墙规则时，需要调用方法
 * cn.hedeoer.firewalld.op.PortRuleService#addOrRemoveOnePortRule(java.lang.String, cn.hedeoer.firewalld.PortRule, java.lang.String)
 */
public class FirewallOpAdapter implements Runnable {

    private static final Logger logger = LoggerFactory.getLogger(FirewallOpAdapter.class);

    @Override
    public void run() {

        // 获取agent节点的唯一标识
        String agentId = AgentIdUtil.loadOrCreateUUID();
        String subStreamKey = agentId + ":sub";
        String groupName = "firewall_" + subStreamKey + "_group";
        String consumerName = "firewall_" + subStreamKey + "_consumer";

//            SimpleStreamConsumer simpleStreamConsumer = new SimpleStreamConsumer(jedis, subStreamKey);

        // 消费流的结果封装
        ResponseResult<List<PortRule>> consumeResult = ResponseResult.success();

        // 不断循环 + block实现不断拉取 指定 stream key的数据，但没有数据时，一直阻塞；当有数据，消费处理，后进入下一次循环

        while (true) {
            // 每次循环都重新获取 Jedis，用完就关闭,这样即使某次消费中 Jedis 发生了超时、阻塞断开、协议污染，下一轮会用全新连接，最大化避免脏连接带来的所有潜在问题
            try (Jedis jedis = RedisUtil.getJedis()) {
                StreamConsumer consumer = new StreamConsumer(jedis, subStreamKey, groupName, consumerName);
                List<StreamEntry> streamEntries = consumer.consumeNewMessages(1, 0);
//                List<StreamEntry> streamEntries1 = simpleStreamConsumer.readNewMessages(1, 0);
                if (streamEntries.isEmpty()) {
                    continue;
                }
                StreamEntry streamEntry = streamEntries.get(0);

                // 转化 streamEntry的fields为java对象
                PortRuleStreamEntry portRuleStreamEntry = fromMap(streamEntry.getFields());
                // 判断此次端口规则操作的类型（PortRuleOpType枚举）
                PortRuleOpType portRuleOpType = judgePortRuleOpType(portRuleStreamEntry);

                PortRuleServiceImpl portRuleService = new PortRuleServiceImpl();
                //
                Map<String, String> requestParams = portRuleStreamEntry.getRequestParams();
                // 防火墙zone
                String zoneName = requestParams.get("zoneName");
                String dataOpType = portRuleStreamEntry.getDataOpType();
                List<PortRule> datas = portRuleStreamEntry.getData();

                logger.info("将进行 {} 操作", portRuleOpType.name());

                List<PortRule> rules = null;
                Boolean consumeResultBoolean = null;
                switch (portRuleOpType) {
                    case QUERY_ALL_PORTRULE:
                        rules = portRuleService.queryAllPortRule(zoneName);
                        if (rules == null) {
                            consumeResult = ResponseResult.fail(rules, "无法获取全部端口规则！！");
                            break;
                        }
                        break;
                    case QUERY_PORTRULES_BY_POLICY_AND_USINGSTATUS:
                        boolean policy = Boolean.parseBoolean(requestParams.get("policy"));
                        boolean isUsing = Boolean.parseBoolean(requestParams.get("isUsing"));
                        rules = portRuleService.queryPortRulesByPolicyAndUsingStatus(zoneName, isUsing, policy);
                        if (rules == null) {
                            consumeResult = ResponseResult.fail(rules, "无法通过policy: " + policy + " 和 isUsing: " + isUsing + " 获取端口规则！！");
                            break;
                        }
                        break;
                    case ADDORREMOVE_ONE_PORTRULE:
                        consumeResultBoolean = portRuleService.addOrRemoveOnePortRule(zoneName, datas.get(0), dataOpType);
                        if (!consumeResultBoolean) {
                            consumeResult = ResponseResult.fail(rules, "无法" + dataOpType + "端口规则");
                            break;
                        }
                        break;
                    case ADDORREMOVE_BATCH_PORTRULES:
                        consumeResultBoolean = portRuleService.addOrRemoveBatchPortRules(zoneName, datas, dataOpType);
                        if (!consumeResultBoolean) {
                            consumeResult = ResponseResult.fail(rules, "无法批量" + dataOpType + "端口规则");
                            break;
                        }
                        break;
                    case UPDATE_ONE_PORTRULE:
                        PortRule old = portRuleStreamEntry.getOld();
                        consumeResultBoolean = portRuleService.updateOnePortRule(zoneName, old, datas.get(0));
                        if (!consumeResultBoolean) {
                            consumeResult = ResponseResult.fail(rules, "无法更新端口规则");
                            break;
                        }
                        break;
                    default:
                        logger.error("不匹配任何规定的端口规则操作，{}", portRuleOpType);
                }
                consumeResult.setData(rules);

                // 加载防火墙使得配置生效
                String status = consumeResult.getStatus();
                if (ResponseStatus.SUCCESS.getResponseCode().equals(consumeResult.getStatus())) {
                    try {
                        WallUtil.reloadFirewall(FireWallType.FIREWALLD);
                        logger.info("重启防火墙 {} 成功", FireWallType.FIREWALLD);
                    } catch (FirewallException e) {
                        throw new RuntimeException(e);
                    }
                }

                // 确认消息处理完成
                StreamEntryID entryID = streamEntry.getID();

                // 发布数据到 stream key （001:pub）
                String pubStreamKey = agentId + ":pub";

                StreamEntryID streamEntryID = publishMessges(jedis, pubStreamKey, entryID, consumeResult);
                jedis.xack(subStreamKey, groupName, entryID);
                logger.info("agent节点：{} 向 streamKey为：{} 的stream发布 StreamEntryID：{}的消息作为响应成功", agentId, pubStreamKey, entryID);
            } catch (RuntimeException e) {
                logger.error("消费过程出错", e);
                // 可选休眠再重试，避免疯循环
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ignored) {
                }
            }
        }


    }

    /**
     * 当成功消费 agentId:sub （比如 001:sub）后，发布消息到agentId:pub（比如 001:pub）。作为master节点发布命令后，agent节点对master节点的响应，master节点需要去
     * 读取指定的streamKey，过滤出entryID对应的响应
     *
     * @param jedis         jedis链接
     * @param streamKey     目标streamkey
     * @param entryID       需要发布的StreamEntry的entryId
     * @param consumeResult 消费 agentId:sub 的结果，可以看作一个响应
     * @return
     */
    private static StreamEntryID publishMessges(Jedis jedis, String streamKey, StreamEntryID entryID, ResponseResult<List<PortRule>> consumeResult) {
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

    /**
     * 判断端口规则的操作类型，对应 接口cn.hedeoer.firewalld.op.PortRuleService下的方法
     *
     * @param portRuleStreamEntry
     * @return PortRuleOpType，如果无法判断，返回null
     */
    private static PortRuleOpType judgePortRuleOpType(PortRuleStreamEntry portRuleStreamEntry) {
        // 该节点的某个资源类型，比如防火墙资源（cn.hedeoer.pojo.FireWallType.UFW 或者 cn.hedeoer.pojo.FireWallType.FIREWALLD）
        String agentComponentType = portRuleStreamEntry.getAgentComponentType();

        // 本次操作防火墙端口规则对应数据操作类型，（insert ， delete，update，query）
        String dataOpType = portRuleStreamEntry.getDataOpType();

        // 本次端口规则操作前的数据，只有操作类型为update时，才会有oldData
        PortRule oldData = portRuleStreamEntry.getOld();

        // 本次端口规则操作后需要达到的目标数据（只有操作类型为insert或者delete时，才会有data ）
        List<PortRule> data = portRuleStreamEntry.getData();

        // 本次端口规则操作的需要的请求参数，只有query时，才会有值
        // queryAllPortRule(String zoneName) /agent_id=?&&zoneName=?
        // queryPortRulesByUsingStatus(String zoneName, Boolean isUsing) /agent_id=?&&zoneName=?&&isUsing=?
        // queryPortRulesByPolicy(String zoneName, Boolean policy) /agent_id=?&&zoneName=?&&policy=?
        Map<String, String> requestParams = portRuleStreamEntry.getRequestParams();

        PortRuleOpType portRuleOpType = null;
        // 查询操作
        if ("query".equals(dataOpType)) {
            if (requestParams.containsKey("isUsing") || requestParams.containsKey("policy")) {
                portRuleOpType = PortRuleOpType.QUERY_PORTRULES_BY_POLICY_AND_USINGSTATUS;
            } else {
                portRuleOpType = PortRuleOpType.QUERY_ALL_PORTRULE;
            }
            // 新增和删除
        } else if (dataOpType.equals("insert") || dataOpType.equals("delete")) {
            int size = data.size();
            if (size > 1) {
                portRuleOpType = PortRuleOpType.ADDORREMOVE_BATCH_PORTRULES;
            } else if (size == 1) {
                portRuleOpType = PortRuleOpType.ADDORREMOVE_ONE_PORTRULE;
            } else {
                logger.warn("操作：{}, 所需要的数据为空，无法进行", dataOpType);
            }
            // 更新
        } else if (dataOpType.equals("update")) {
            portRuleOpType = PortRuleOpType.UPDATE_ONE_PORTRULE;
        }

        return portRuleOpType;
    }


    /**
     * 端口规则操作类型
     */
    private enum PortRuleOpType {
        QUERY_ALL_PORTRULE,
        //        QUERY_PORTRULES_BY_USINGSTATUS,
//        QUERY_PORTRULES_BY_POLICY,
        QUERY_PORTRULES_BY_POLICY_AND_USINGSTATUS,
        ADDORREMOVE_ONE_PORTRULE,
        ADDORREMOVE_BATCH_PORTRULES,
        UPDATE_ONE_PORTRULE;
    }

    @NoArgsConstructor
    @AllArgsConstructor
    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    @Builder
    public static class PortRuleStreamEntry {
        @JsonProperty("agent_id")
        private String agentId;
        @JsonProperty("agent_component_type")
        private String agentComponentType;
        @JsonProperty("data_op_type")
        private String dataOpType;
        @JsonProperty("request_params")
        private Map<String, String> requestParams;
        @JsonProperty("ts")
        private String ts;
        @JsonProperty("primary_key_columns")
        private List<String> primaryKeyColumns;
        @JsonProperty("data")
        private List<PortRule> data;
        @JsonProperty("old")
        private PortRule old;
    }

    /**
     * 将map转化为 PortRuleStreamEntry 对象
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
    public static PortRuleStreamEntry fromMap(Map<String, String> map) {
        PortRuleStreamEntry entry = null;
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            // 非空参数
            String agentId = map.get("agent_id");
            String agentComponentType = map.get("agent_component_type");
            String dataOpType = map.get("data_op_type");
            Map<String, String> requestParams = objectMapper.readValue(map.get("request_params"), new TypeReference<Map<String, String>>() {
            });
            String ts = map.get("ts");

            // 可选参数
            List<String> primaryKeyColumns = new ArrayList<String>();
            if (map.containsKey("primary_key_columns")) {
                primaryKeyColumns = objectMapper.readValue(map.get("primary_key_columns"), new TypeReference<List<String>>() {
                });
            }

            // 可选参数
            List<PortRule> data = new ArrayList<PortRule>();
            if (map.containsKey("data")) {
                data = objectMapper.readValue(map.get("data"), new TypeReference<List<PortRule>>() {
                });
            }

            // 可选参数
            PortRule old = new PortRule();
            if (map.containsKey("old")) {
                old = objectMapper.readValue(map.get("old"), new TypeReference<PortRule>() {
                });
            }


            entry = PortRuleStreamEntry.builder()
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


}
