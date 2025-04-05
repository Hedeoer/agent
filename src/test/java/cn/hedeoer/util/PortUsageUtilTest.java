package cn.hedeoer.util;

import org.junit.Test;

import java.util.List;

public class PortUsageUtilTest {

    @Test
    public void checkPortUsage() {
        System.out.println(PortUsageUtil.getProcessCommandName(34343));
    }

}