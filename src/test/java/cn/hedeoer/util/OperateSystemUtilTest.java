package cn.hedeoer.util;

import org.junit.Test;
import org.slf4j.LoggerFactory;

import static org.junit.Assert.*;

public class OperateSystemUtilTest {

    @Test
    public void getCpuUsage()  {
        String cpuUsage = OperateSystemUtil.getCpuUsage();
        String memoryUsage = OperateSystemUtil.getMemoryUsage();
        String avgDiskUsage = OperateSystemUtil.getAvgDiskUsage();
        System.out.println(cpuUsage +":"+ memoryUsage +":"+ avgDiskUsage);
    }
}