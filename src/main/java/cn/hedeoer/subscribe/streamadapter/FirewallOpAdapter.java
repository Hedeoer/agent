package cn.hedeoer.subscribe.streamadapter;

import cn.hedeoer.common.ResponseResult;
import cn.hedeoer.firewalld.PortRule;
import cn.hedeoer.firewalld.op.PortRuleServiceImpl;
import cn.hedeoer.subscribe.StreamConsumer;
import cn.hedeoer.subscribe.StreamProducer;
import cn.hedeoer.util.RedisUtil;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.StreamEntryID;
import redis.clients.jedis.resps.StreamEntry;

import java.util.List;
import java.util.Map;

/**
 * 对redis stream的 数据做适配响应，比如 当添加或者删除一个防火墙规则时，需要调用方法
 * cn.hedeoer.firewalld.op.PortRuleService#addOrRemoveOnePortRule(java.lang.String, cn.hedeoer.firewalld.PortRule, java.lang.String)
 */
public class FirewallOpAdapter {

    private static final Logger logger = LoggerFactory.getLogger(FirewallOpAdapter.class);


    // 获取 redis stream的某个 stream key下的数据，此处的stream key为 agent机器节点的唯一标识
    // 解析 stream 中的数据
    // 判断调用具体的方法

    public static void main(String[] args) {
        Jedis jedis = RedisUtil.getJedis();
        String agentId = "001:sub";
        String groupName = "firewall_" + agentId + "_group";
        String consumerName = "firewall_" + agentId + "_consumer";
        StreamConsumer consumer = new StreamConsumer(
                jedis, agentId, groupName, consumerName);

        // 消费流的结果封装
        ResponseResult<List<PortRule>> consumeResult = ResponseResult.success();

        // 不断循环 + block实现不断拉取 指定 stream key的数据，但没有数据时，一直阻塞；当有数据，消费处理，后进入下一次循环
        while (true) {

            List<StreamEntry> streamEntries = consumer.consumeNewMessages(1, 0);
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

            logger.info("将进行{} 操作", portRuleOpType.name());

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
                case QUERY_PORTRULES_BY_POLICY:
                    boolean policy = Boolean.parseBoolean(requestParams.get("policy"));
                    rules = portRuleService.queryPortRulesByPolicy(zoneName, policy);
                    if (rules == null){
                        consumeResult = ResponseResult.fail(rules, "无法通过policy获取端口规则！！");
                        break;
                    }
                    break;
                case QUERY_PORTRULES_BY_USINGSTATUS:
                    boolean isUsing = Boolean.parseBoolean(requestParams.get("isUsing"));
                    rules = portRuleService.queryPortRulesByUsingStatus(zoneName, isUsing);
                    if(rules == null){
                        consumeResult = ResponseResult.fail(rules, "无法通过isUsing获取端口规则！！");
                        break;
                    }
                    break;
                case ADDORREMOVE_ONE_PORTRULE:
                     consumeResultBoolean= portRuleService.addOrRemoveOnePortRule(zoneName, datas.get(0), dataOpType);
                    if (!consumeResultBoolean){
                        consumeResult = ResponseResult.fail(rules,"无法"+ dataOpType +"端口规则");
                        break;
                    }
                    break;
                case ADDORREMOVE_BATCH_PORTRULES:
                    consumeResultBoolean = portRuleService.addOrRemoveBatchPortRules(zoneName, datas, dataOpType);
                    if (!consumeResultBoolean){
                        consumeResult = ResponseResult.fail(rules,"无法批量"+ dataOpType +"端口规则");
                        break;
                    }
                    break;
                case UPDATE_ONE_PORTRULE:
                    PortRule old = portRuleStreamEntry.getOld();
                    consumeResultBoolean = portRuleService.updateOnePortRule(zoneName, datas.get(0), old);
                    if (!consumeResultBoolean){
                        consumeResult = ResponseResult.fail(rules,"无法更新端口规则");
                        break;
                    }
                    break;
                default:
                    logger.error("不匹配任何规定的端口规则操作，{}", portRuleOpType);
            }
            consumeResult.setData(rules);

            // 确认消息处理完成
            StreamEntryID entryID = streamEntry.getID();
            jedis.xack(agentId, groupName, entryID);

            // 发布数据到 stream key （001:pub）
            String streamKey = "001:pub";

            StreamEntryID streamEntryID = publishMessges(jedis, streamKey, entryID, consumeResult);
        }


    }

    /**
     * 当成功消费 agentId:sub （比如 001:sub）后，发布消息到agentId:pub（比如 001:pub）
     *
     * @param jedis jedis链接
     * @param streamKey 目标streamkey
     * @param entryID 需要发布的StreamEntry的entryId
     * @param consumeResult  消费 agentId:sub 的结果，可以看作一个响应
     * @return
     */
    private static StreamEntryID publishMessges(Jedis jedis, String streamKey, StreamEntryID entryID, ResponseResult<List<PortRule>> consumeResult) {
        // todo 1.  发布消息时如何指定 entryID， 2. agent向master注册时需要设计agent_Id的生成规则，3. master的对于agent响应的数据是否需要持久化
        StreamProducer producer = new StreamProducer(jedis, streamKey);
        producer.publishMessage()
        producer.close();
        return null;
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
            if (requestParams.containsKey("isUsing")) {
                portRuleOpType = PortRuleOpType.QUERY_PORTRULES_BY_USINGSTATUS;
            } else if (requestParams.containsKey("policy")) {
                portRuleOpType = PortRuleOpType.QUERY_PORTRULES_BY_POLICY;
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
        QUERY_PORTRULES_BY_USINGSTATUS,
        QUERY_PORTRULES_BY_POLICY,
        ADDORREMOVE_ONE_PORTRULE,
        ADDORREMOVE_BATCH_PORTRULES,
        UPDATE_ONE_PORTRULE;
    }

    @NoArgsConstructor
    @AllArgsConstructor
    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
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

    public static PortRuleStreamEntry fromMap(Map<String, String> map) {
        PortRuleStreamEntry entry = null;
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            entry = new PortRuleStreamEntry();
            entry.setAgentId(map.get("agent_id"));
            entry.setAgentComponentType(map.get("agent_component_type"));
            entry.setDataOpType(map.get("data_op_type"));
            entry.setRequestParams(objectMapper.readValue(map.get("request_params"), new TypeReference<Map<String, String>>() {
            }));
            entry.setTs(map.get("ts"));

            entry.setPrimaryKeyColumns(objectMapper.readValue(map.get("primary_key_columns"), new TypeReference<List<String>>() {
            }));
            entry.setData(objectMapper.readValue(map.get("data"), new TypeReference<List<PortRule>>() {
            }));
            entry.setOld(objectMapper.readValue(map.get("old"), new TypeReference<PortRule>() {
            }));
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        return entry;
    }


}
