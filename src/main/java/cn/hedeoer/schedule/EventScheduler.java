package cn.hedeoer.schedule;

import cn.hedeoer.agent.HeartBeat;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class EventScheduler {
    private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(Runtime.getRuntime().availableProcessors() + 1);

    /**
     * agent节点向master周期汇报心跳
     */
    public static void scheduleHeartBeat(){
        HeartBeat heartBeat = new HeartBeat();
        scheduler.scheduleAtFixedRate(heartBeat, 0L, 30, TimeUnit.SECONDS);
    }
}
