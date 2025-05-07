package cn.hedeoer.firewall.ufw.op;

import org.junit.Test;

import java.io.IOException;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.*;

public class PortRuleServiceImplByUFWTest {

    @Test
    public void covertUfwRuleToDetailStyle() throws IOException, InterruptedException, TimeoutException {
        PortRuleServiceImplByUFW.covertUfwRuleToDetailStyle();
        //sudo ufw delete 3 --force
        //sudo ufw delete 4 --force
        //sudo ufw delete 6 --force
        //sudo ufw delete 7 --force
        //sudo ufw delete 8 --force

        //# 规则6: 53 ALLOW OUT Anywhere (out)
        //sudo ufw allow out 53
        //
        //# 规则7: 3000:3100/tcp ALLOW IN 192.168.1.0/24 # Allow TCP traffic to ports 3000-3100 from local network
        //sudo ufw allow from 192.168.1.0/24 to any port 3000:3100 proto tcp
        //
        //# 规则8: 22/udp ALLOW IN Anywhere
        //sudo ufw allow 22/udp
        //
        //# 规则9: 80/tcp (v6) ALLOW IN Anywhere (v6) # 允许HTTP入站
        //sudo ufw allow from ::/0 to any port 80 proto tcp
        //
        //# 规则10: 22/tcp (v6) ALLOW IN Anywhere (v6)
        //sudo ufw allow from ::/0 to any port 22 proto tcp
        //
        //# 规则11: 4567 (v6) ALLOW IN Anywhere (v6)
        //sudo ufw allow from ::/0 to any port 4567
        //
        //# 规则12: 3000:3100/tcp (v6) ALLOW IN Anywhere (v6)
        //sudo ufw allow from ::/0 to any port 3000:3100 proto tcp
        //
        //# 规则13: 53 (v6) ALLOW OUT Anywhere (v6) (out)
        //sudo ufw allow out from any to ::/0 port 53
        //
        //# 规则14: 8100/tcp ALLOW IN 2001:db8::/64 # Allow TCP traffic from IPv6 network to web ports
        //sudo ufw allow from 2001:db8::/64 to any port 8100 proto tcp
        //
        //# 规则15: 8101/tcp ALLOW IN 2001:db8::/64 # Allow TCP traffic from IPv6 network to web port 8101
        //sudo ufw allow from 2001:db8::/64 to any port 8101 proto tcp
        //
        //# 规则16: 8102/tcp ALLOW IN 2001:db8::/64 # Explicitly IPv6 rule
        //sudo ufw allow from 2001:db8::/64 to any port 8102 proto tcp
        //
        //# 规则17: 8103 ALLOW IN 2001:db8::/64 # Allow TCP traffic from IPv6 network to web ports8101
        //sudo ufw allow from 2001:db8::/64 to any port 8103
        //
        //# 规则18: 22/udp (v6) ALLOW IN Anywhere (v6)
        //sudo ufw allow from ::/0 to any port 22 proto udp
    }
}