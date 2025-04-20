package cn.hedeoer;

import cn.hedeoer.subscribe.streamadapter.FirewallOpAdapter;
import cn.hedeoer.util.FirewallDetector;
import cn.hedeoer.util.OperateSystemUtil;
import cn.hedeoer.util.ThreadPoolUtil;

import java.util.Map;
import java.util.concurrent.ThreadPoolExecutor;

public class Main {
    public static void main(String[] args) {

        // 启动新线程，不断消费来自master节点的命令
        ThreadPoolExecutor commonPool = ThreadPoolUtil.getCommonPool();
        FirewallOpAdapter adapter = new FirewallOpAdapter();

        commonPool.execute(adapter);


    }
}