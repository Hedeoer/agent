package cn.hedeoer.util;

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
        List<PortMonitorUtils.PortInfo> port80Info = PortMonitorUtils.getPortUsage(6532);
        for (PortMonitorUtils.PortInfo info : port80Info) {
            System.out.println(info);
        }

        System.out.println("端口6532是否被占用: " + isPortInUse(6532));

        // 示例2: 获取指定端口列表的使用情况
        System.out.println("\n指定端口列表的使用情况:");
        List<String> ports = Arrays.asList("6532");
        List<PortMonitorUtils.PortInfo> portListInfo = getPortsUsage(ports);
        for (PortMonitorUtils.PortInfo info : portListInfo) {
            System.out.println(info);
        }
    }
}