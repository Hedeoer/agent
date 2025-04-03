package cn.hedeoer;

import cn.hedeoer.util.FirewallDetector;
import cn.hedeoer.util.OperateSystemUtil;

import java.util.Map;

public class Main {
    public static void main(String[] args) {

        Map<String, FirewallDetector.FirewallStatus> map = FirewallDetector.detectFirewalls();
        map.entrySet().forEach(entry -> System.out.println(entry.getKey() + ":" + entry.getValue()) );

        System.out.println(FirewallDetector.hasMultipleFirewallsEnabled());

    }
}