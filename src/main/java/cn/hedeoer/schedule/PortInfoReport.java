package cn.hedeoer.schedule;

import cn.hedeoer.pojo.PortInfo;
import cn.hedeoer.util.AgentIdUtil;
import cn.hedeoer.util.PortMonitorUtils;
import cn.hedeoer.util.RedisUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

public class PortInfoReport implements Runnable{

    private static final Logger logger = LoggerFactory.getLogger(PortInfoReport.class);
    private final ObjectMapper objectMapper = new ObjectMapper();
    private Integer heartBeatGap;
    // 使用 CopyOnWriteArrayList 保存上一次端口信息
    private final List<PortInfo> lastPortInfos = new CopyOnWriteArrayList<>();

    public  PortInfoReport(){}

    public  PortInfoReport(Integer heartBeatGap){
        this.heartBeatGap = heartBeatGap;
    }


    @Override
    public void run() {
        boolean b = reportPortInfo(lastPortInfos);
    }

    public boolean reportPortInfo(List<PortInfo> lastPortInfos) {
        try (Jedis jedis = RedisUtil.getJedis()) {


            boolean res = false;
            // 节点唯一表似乎
            String agentId = AgentIdUtil.loadOrCreateUUID();

            // 获取 快速查出 1024-65535 端口范围 内目前被使用的端口号情况
            List<PortInfo> currentPortInfos = PortMonitorUtils.getUsedPortsAbove22();

            // 和上次比较是否有端口使用情况发生变化？
            Boolean hasChange = hasPortChanges(lastPortInfos,currentPortInfos);

            String portInfoHashTableName = "firewall:portInfo";
            String redisServerSecondsTime = RedisUtil.getRedisServerTime();

            ObjectNode jsonNode = objectMapper.createObjectNode();
            // redis服务器时间
            jsonNode.put("ts",redisServerSecondsTime);
            // agent节点本次将要上报的节点使用情况和上次上报的是否有变更；上报给master节点使用
            jsonNode.put("hasChange",hasChange);
            // 节点本次的节点使用情况
            jsonNode.set("reportPortInfos", objectMapper.valueToTree(currentPortInfos));

            long hset = jedis.hset(portInfoHashTableName, agentId, objectMapper.writeValueAsString(jsonNode));

            if (hset == 0 || hset == 1) {
                res = true;
            }else{
                logger.error("agentId：{} 向 master节点发送端口使用情况失败，当前配置发送时间间隔 : {} 秒",agentId, this.heartBeatGap);
            }

            synchronized (lastPortInfos) {
                lastPortInfos.clear();
                lastPortInfos.addAll(currentPortInfos);
            }

            return res;
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     *
     * @param lastPortInfos
     * @param currentPortInfos
     * @return
     */
    private Boolean hasPortChanges(List<PortInfo> lastPortInfos, List<PortInfo> currentPortInfos) {
        // 将 List 转换为 Set 进行比较
        Set<PortInfo> lastSet = new HashSet<>(lastPortInfos);
        Set<PortInfo> currentSet = new HashSet<>(currentPortInfos);

        // 判断是否有变更
        return  !lastSet.equals(currentSet);
    }


}
