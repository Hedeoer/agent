package cn.hedeoer.firewall.ufw;

import org.junit.Test;

import static org.junit.Assert.*;

public class UfwStatusTest {

    @Test
    public void parse() {
        String output = "Status: active\n" +
                "Logging: on (low)\n" +
                "Default: deny (incoming), allow (outgoing), disabled (routed)\n" +
                "New profiles: skip\n" +
                "\n" +
                "To                         Action      From\n" +
                "--                         ------      ----\n" +
                "22                         ALLOW IN    Anywhere                  \n" +
                "80/tcp                     ALLOW IN    Anywhere                   # 允许HTTP入站\n" +
                "443/tcp                    REJECT IN   192.168.1.100              # 拒绝特定IP访问HTTPS\n" +
                "22/tcp                     LIMIT IN    Anywhere                   # 限制SSH入站速率\n" +
                "4567                       ALLOW IN    Anywhere                  \n" +
                "3000:3100/tcp              ALLOW IN    Anywhere                  \n" +
                "22 (v6)                    ALLOW IN    Anywhere (v6)             \n" +
                "80/tcp (v6)                ALLOW IN    Anywhere (v6)              # 允许HTTP入站\n" +
                "22/tcp (v6)                LIMIT IN    Anywhere (v6)              # 限制SSH入站速率\n" +
                "4567 (v6)                  ALLOW IN    Anywhere (v6)             \n" +
                "3000:3100/tcp (v6)         ALLOW IN    Anywhere (v6)             \n" +
                "\n" +
                "53                         ALLOW OUT   Anywhere                  \n" +
                "53 (v6)                    ALLOW OUT   Anywhere (v6)";

        UfwStatus status = UfwStatus.parse(output);
        System.out.println(status.getRules().size());


    }
}