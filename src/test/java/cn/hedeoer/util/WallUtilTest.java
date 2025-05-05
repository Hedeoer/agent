package cn.hedeoer.util;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class WallUtilTest {

    @Test
    public void getZoneNames() {
        List<String> zoneNames =
                WallUtil.getZoneNames();

        zoneNames.forEach(System.out::println);
    }

    @Test
    public void getWallType() {
        System.out.println(WallUtil.getFirewallType());
    }
}