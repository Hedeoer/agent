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

    @Test
    public void strTest() {
        String command = "ipv4/ipv6 sdfaf";
        String ipv4Command = command.replace("ipv4/ipv6", "ipv4");
        String ipv6Command = ipv4Command.replace("ipv4", "ipv6");

        System.out.println(command);
        System.out.println(ipv4Command);
        System.out.println(ipv6Command);
    }
}