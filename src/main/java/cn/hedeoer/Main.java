package cn.hedeoer;

import cn.hedeoer.agent.HeartBeat;
import cn.hedeoer.schedule.EventScheduler;
import cn.hedeoer.subscribe.streamadapter.FirewallOpAdapter;
import cn.hedeoer.util.AgentIdUtil;
import cn.hedeoer.util.FirewallDetector;
import cn.hedeoer.util.OperateSystemUtil;
import cn.hedeoer.util.ThreadPoolUtil;

import java.util.Map;
import java.util.concurrent.ThreadPoolExecutor;

public class Main {
    public static void main(String[] args) {

        // 获取线程池
        ThreadPoolExecutor commonPool = ThreadPoolUtil.getCommonPool();

        // 1.首次启动时，并获取agentId,
        String agentId = AgentIdUtil.loadOrCreateUUID();

        // agent节点的心跳汇报
        // 向master注册(通过使用 redis hash方式， hash表名字 heartbeats, key为agentId, vaule为向master节点上报时的时间戳)
        // 获取redis服务器本地时间戳，避免一旦集群里服务器时间不同步，心跳状态的判断就容易出错
        // 周期性执行hset命令，向master节点汇报心跳，比如 30秒
        EventScheduler.scheduleHeartBeat();


        // master节点的接收来自agent节点的心跳
        // 将所有汇报心跳的agentId数据持久化
        // 如何区分agent节点心跳是否是首次？如果是首次，需要持久化agent节点信息;不是首次，需要判断agent节点是否离线？
        //     通过对比redis服务器时间戳和心跳汇报的时间戳间隔，比如超过30秒，表示agent节点离线

        // 2.启动新线程，不断消费来自master节点的命令
        FirewallOpAdapter adapter = new FirewallOpAdapter();
        commonPool.execute(adapter);





    }
}