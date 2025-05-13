package cn.hedeoer.util;

import org.junit.Test;

public class YamlUtilTest {

    @Test
    public void getYamlConfig() {
        YamlUtil.getYamlConfig("ssh").forEach((key, value) -> {
            System.out.print(key);
            System.out.println(value);
        });
    }
}