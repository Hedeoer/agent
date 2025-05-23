package cn.hedeoer.subscribe.streamadapter;

import cn.hedeoer.firewall.PortRuleService;
import cn.hedeoer.firewall.ufw.op.PortRuleServiceImplByUFW;
import cn.hedeoer.schedule.HeartBeat;
import cn.hedeoer.common.entity.ResponseResult;
import cn.hedeoer.common.enmu.ResponseStatus;
import cn.hedeoer.common.entity.AbstractFirewallRule;
import cn.hedeoer.common.entity.PortRule;
import cn.hedeoer.firewall.firewalld.exception.FirewallException;
import cn.hedeoer.firewall.firewalld.op.PortRuleServiceImplByFirewalld;
import cn.hedeoer.common.enmu.FireWallType;
import cn.hedeoer.subscribe.StreamConsumer;
import cn.hedeoer.subscribe.StreamProducer;
import cn.hedeoer.util.AgentIdUtil;
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
import redis.clients.jedis.resps.StreamEntry;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 对redis stream的 数据做适配响应，比如 当添加或者删除一个防火墙规则时，需要调用方法
 * cn.hedeoer.firewalld.op.PortRuleService#addOrRemoveOnePortRule(java.lang.String, cn.hedeoer.common.entity.PortRule, java.lang.String)
 */
public class FirewallOpAdapter implements Runnable {

    private static final Logger logger = LoggerFactory.getLogger(FirewallOpAdapter.class);
    private PortRuleService portRuleService;
    private final FireWallType firewallType;

    public FirewallOpAdapter() {
        FireWallType firewallType = WallUtil.getFirewallType();
        // 通过防火墙类型选择对应的实现类
        if (FireWallType.UFW.equals(firewallType)) {
            this.portRuleService = new PortRuleServiceImplByUFW();
        } else if (FireWallType.FIREWALLD.equals(firewallType)) {
            this.portRuleService = new PortRuleServiceImplByFirewalld();
        } else {
            logger.error("不支持的防火墙类型");
        }

        // 防火墙类型
        this.firewallType = firewallType;

    }

    @Override
    public void run() {

        // 获取agent节点的唯一标识
        String agentId = AgentIdUtil.loadOrCreateUUID();
        String subStreamKey = "sub:" + agentId + ":" + "portRule";
        String groupName = "firewall_" + subStreamKey + "_group";
        String consumerName = groupName + "_consumer";
        String pubStreamKey = "pub:" + agentId + ":" + "portRule";

//            SimpleStreamConsumer simpleStreamConsumer = new SimpleStreamConsumer(jedis, subStreamKey);

        // 消费流的结果封装
        ResponseResult<List<PortRule>> consumeResult = ResponseResult.success();

        // 不断循环 + block实现不断拉取 指定 stream key的数据，但没有数据时，一直阻塞；当有数据，消费处理，后进入下一次循环

        while (true) {
            // 每次循环都重新获取 Jedis，用完就关闭,这样即使某次消费中 Jedis 发生了超时、阻塞断开、协议污染，下一轮会用全新连接，最大化避免脏连接带来的所有潜在问题
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
                PortRuleStreamEntry portRuleStreamEntry = fromMap(streamEntry.getFields());

                // 判断此次端口规则操作的类型（PortRuleOpType枚举）
                PortRuleOpType portRuleOpType = judgePortRuleOpType(portRuleStreamEntry);

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
                            consumeResult = ResponseResult.fail(rules, "无法获取区域：" + zoneName + " 的全部端口规则！！");
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
                        consumeResultBoolean = portRuleService.addOrRemoveOnePortRule(zoneName, datas.get(0), dataOpType.toLowerCase());
                        if (!consumeResultBoolean) {
                            consumeResult = ResponseResult.fail(rules, "无法" + dataOpType + "端口规则");
                            break;
                        }
                        break;
                    case ADDORREMOVE_BATCH_PORTRULES:
                        // if list<PortRule> need group by getting the number of zoneName(distinct)
                        // not
                        // need group
                        Map<String, List<PortRule>> batchPortRulesMap = getDistinctZoneNamesFromPortRules(datas);
                        for (Map.Entry<String, List<PortRule>> map : batchPortRulesMap.entrySet()) {
                            consumeResultBoolean = portRuleService.addOrRemoveBatchPortRules(zoneName, map.getValue(), dataOpType.toLowerCase());
                        }

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
                    case OPTIONS:
                        consumeResultBoolean = new HeartBeat().sendHearBeat();
                        if (!consumeResultBoolean) {
                            consumeResult = ResponseResult.fail(rules, "无法手动触发心跳汇报给主节点");
                            break;
                        }
                        break;
                    default:
                        logger.error("不匹配任何规定的端口规则操作，{}", portRuleOpType);
                }
                consumeResult.setData(rules);

                // 非查询操作并且要是firewalld防火墙工具才需要加载防火墙使得配置生效
                if (ResponseStatus.SUCCESS.getResponseCode().equals(consumeResult.getStatus())
                        && !("query".equals(portRuleStreamEntry.getDataOpType()))
                        && firewallType.equals(FireWallType.FIREWALLD)) {
                    try {
                        WallUtil.reloadFirewall(FireWallType.FIREWALLD);
                        logger.info("重启防火墙 {} 成功", FireWallType.FIREWALLD);
                    } catch (FirewallException e) {
                        throw new RuntimeException(e);
                    }
                }

                // 确认消息处理完成
                StreamEntryID entryID = streamEntry.getID();

                // 发布数据到 stream key （pub:001）
                StreamEntryID streamEntryID = publishMessges(jedis, subStreamKey, entryID, consumeResult);
                jedis.xack(pubStreamKey, groupName, entryID);
                logger.info("agent节点：{} 向 streamKey为：{} 的stream发布 StreamEntryID：{}的消息作为响应成功", agentId, subStreamKey, entryID);
            } catch (RuntimeException e) {
                logger.error("消费过程出错", e);
                // 可选休眠再重试，避免疯循环
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ignored) {
                }
            } catch (FirewallException e) {
                throw new RuntimeException(e);
            }
        }


    }

    /**
     * get portrules group by zonename
     *
     * @param datas total portrules
     * @return map
     */
    private Map<String, List<PortRule>> getDistinctZoneNamesFromPortRules(List<PortRule> datas) {
        HashMap<String, List<PortRule>> map = new HashMap<>();
        ArrayList<PortRule> list = new ArrayList<>();

        if (datas == null || datas.isEmpty()) {
            map.put(null, list);
            return map;
        }

        List<String> zoneNames = datas.stream()
                .map(AbstractFirewallRule::getZone)
                .distinct()
                .collect(Collectors.toList());

        for (String zoneName : zoneNames) {
            map.put(zoneName, new ArrayList<PortRule>());
        }

        for (PortRule data : datas) {
            String zoneNameFromPortRule = data.getZone();
            for (Map.Entry<String, List<PortRule>> subMap : map.entrySet()) {
                if (map.containsKey(zoneNameFromPortRule)) {
                    map.get(zoneNameFromPortRule)
                            .add(data);
                }
            }
        }

        return map;
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
        //  master获取 agentId:pub 流数据逻辑 master发布命令后去读取指定的steam即可获取 响应，可以考虑重复读取减少网络波动影响
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
        // 该节点的某个资源类型，比如防火墙资源（cn.hedeoer.common.enmu.FireWallType.UFW 或者 cn.hedeoer.common.enmu.FireWallType.FIREWALLD）
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
        if ("QUERY".equals(dataOpType)) {
            if (requestParams.containsKey("isUsing") || requestParams.containsKey("policy")) {
                portRuleOpType = PortRuleOpType.QUERY_PORTRULES_BY_POLICY_AND_USINGSTATUS;
            } else {
                portRuleOpType = PortRuleOpType.QUERY_ALL_PORTRULE;
            }
            // 新增和删除
        } else if (dataOpType.equals("INSERT") || dataOpType.equals("DELETE")) {
            int size = data.size();
            if (size > 1) {
                portRuleOpType = PortRuleOpType.ADDORREMOVE_BATCH_PORTRULES;
            } else if (size == 1) {
                portRuleOpType = PortRuleOpType.ADDORREMOVE_ONE_PORTRULE;
            } else {
                logger.warn("操作：{}, 所需要的数据为空，无法进行", dataOpType);
            }
            // 更新
        } else if (dataOpType.equals("UPDATE")) {
            portRuleOpType = PortRuleOpType.UPDATE_ONE_PORTRULE;
        } else if (dataOpType.equals("OPTIONS")) {
            portRuleOpType = PortRuleOpType.OPTIONS;
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
        UPDATE_ONE_PORTRULE,
        // 手动发送心跳
        OPTIONS;
    }

    @NoArgsConstructor
    @AllArgsConstructor
    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    @Builder
    public static class PortRuleStreamEntry {

        private String agentId;

        private String agentComponentType;

        private String dataOpType;

        private Map<String, String> requestParams;

        private String ts;

        private List<String> primaryKeyColumns;

        private List<PortRule> data;

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
