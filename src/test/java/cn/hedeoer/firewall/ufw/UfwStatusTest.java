package cn.hedeoer.firewall.ufw;

import org.junit.Test;

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

        String umberStr = "Status: active\n" +
                "\n" +
                "     To                         Action      From\n" +
                "     --                         ------      ----\n" +
                "[ 1] 22                         ALLOW IN    Anywhere                  \n" +
                "[ 2] 80/tcp                     ALLOW IN    Anywhere                   # 允许HTTP入站\n" +
                "[ 3] 443/tcp                    REJECT IN   192.168.1.100              # 拒绝特定IP访问HTTPS\n" +
                "[ 4] 22/tcp                     LIMIT IN    Anywhere                   # 限制SSH入站速率\n" +
                "[ 5] 4567                       ALLOW IN    Anywhere                  \n" +
                "[ 6] 3000:3100/tcp              ALLOW IN    Anywhere                  \n" +
                "[ 7] 53                         ALLOW OUT   Anywhere                   (out)\n" +
                "[ 8] 3000:3100/tcp              ALLOW IN    192.168.1.0/24             # Allow TCP traffic to ports 3000-3100 from local network\n" +
                "[ 9] 22 (v6)                    ALLOW IN    Anywhere (v6)             \n" +
                "[10] 80/tcp (v6)                ALLOW IN    Anywhere (v6)              # 允许HTTP入站\n" +
                "[11] 22/tcp (v6)                LIMIT IN    Anywhere (v6)              # 限制SSH入站速率\n" +
                "[12] 4567 (v6)                  ALLOW IN    Anywhere (v6)             \n" +
                "[13] 3000:3100/tcp (v6)         ALLOW IN    Anywhere (v6)             \n" +
                "[14] 53 (v6)                    ALLOW OUT   Anywhere (v6)              (out)\n" +
                "[15] 8100/tcp                   ALLOW IN    2001:db8::/64              # Allow TCP traffic from IPv6 network to web ports\n" +
                "[16] 8101/tcp                   ALLOW IN    2001:db8::/64              # Allow TCP traffic from IPv6 network to web port 8101\n" +
                "[17] 8102/tcp                   ALLOW IN    2001:db8::/64              # Explicitly IPv6 rule\n" +
                "[18] 8103                       ALLOW IN    2001:db8::/64              # Allow TCP traffic from IPv6 network to web ports8101";

        UfwStatus status = UfwStatus.parse(output,umberStr);
        System.out.println(status.getRules().size());

//sudo ufw --force delete 18
//sudo ufw --force delete 17
//sudo ufw --force delete 16
//sudo ufw --force delete 15
//sudo ufw --force delete 14
//sudo ufw --force delete 12
//sudo ufw --force delete 11
//sudo ufw --force delete 10
//sudo ufw --force delete 9
//sudo ufw --force delete 8
//sudo ufw --force delete 7
//sudo ufw --force delete 5
//sudo ufw --force delete 4
//sudo ufw --force delete 3
//sudo ufw --force delete 2


    }
}