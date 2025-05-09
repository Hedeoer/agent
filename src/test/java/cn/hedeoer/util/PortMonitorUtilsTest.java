package cn.hedeoer.util;

import cn.hedeoer.pojo.PortInfo;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static cn.hedeoer.util.PortMonitorUtils.getPortsUsage;
import static cn.hedeoer.util.PortMonitorUtils.isPortInUse;

public class PortMonitorUtilsTest {

    @Test
    public void getPortsUsageTest() {
        // 示例1: 获取80端口的使用情况
        System.out.println("端口 6532 的使用情况:");
        List<PortInfo> port80Info = PortMonitorUtils.getPortUsage("6532");
        for (PortInfo info : port80Info) {
            System.out.println(info);
        }

        System.out.println("端口22是否被占用: " + isPortInUse("22"));

        // 示例2: 获取指定端口列表的使用情况
        System.out.println("\n指定端口列表的使用情况:");
        List<String> ports = Arrays.asList("22");
        List<PortInfo> portListInfo = getPortsUsage(ports);
        for (PortInfo info : portListInfo) {
            System.out.println(info);
        }
    }

    @Test
    public void isPortsInUse() {
        System.out.println(PortMonitorUtils.getPortsInUse("9080,9081","tcp"));
        System.out.println(PortMonitorUtils.getPortsInUse("8083-8084","tcp"));
        System.out.println(PortMonitorUtils.getPortsInUse("6532","tcp"));
        System.out.println(PortMonitorUtils.getPortsInUse("6533","tcp"));
        System.out.println(PortMonitorUtils.getPortsInUse("","tcp"));
        System.out.println(PortMonitorUtils.getPortsInUse("22","tcp"));
    }

    @Test
    public void getUsedPortsAbove1024() {
        List<PortInfo> list = PortMonitorUtils.getUsedPortsAbove22();
        list.stream().filter(l -> l.getPortNumber() == 22).forEach(System.out::println);
    }
}