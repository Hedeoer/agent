package cn.hedeoer.util;

import cn.hedeoer.common.enmu.FirewallOperationType;
import org.junit.Test;

import java.util.List;

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

    @Test
    public void firewallStatusTest(){
        System.out.println(WallUtil.getFirewallStatusInfo());
    }
}