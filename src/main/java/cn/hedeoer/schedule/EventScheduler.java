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
        Integer heartBeatGap = 30;
        HeartBeat heartBeat = new HeartBeat(heartBeatGap);
        scheduler.scheduleAtFixedRate(heartBeat, 0L, heartBeatGap, TimeUnit.SECONDS);
    }
}
