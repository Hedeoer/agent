package cn.hedeoer.util;

import cn.hedeoer.common.enmu.FireWallType;
import cn.hedeoer.firewall.ufw.UfwRuleConverterWithYourParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.concurrent.TimeoutException;

public class InitUtil {

    private static final Logger logger = LoggerFactory.getLogger(InitUtil.class);

    public static Boolean init() {

        Boolean result = true;

        //判读防火墙工具类型
        //执行对应的初始化工作
        FireWallType firewallType = WallUtil.getFirewallType();
        if (FireWallType.FIREWALLD.equals(firewallType)) {
            // todo firewalld需要检查工作
        }else if (FireWallType.UFW.equals(firewallType)) {
            // todo ufw需要检查工作
            try {
                UfwRuleConverterWithYourParser.covertUfwRuleToDetailStyle();
            } catch (IOException | InterruptedException | TimeoutException e) {
                result =false;
                logger.error(e.getMessage());
                System.exit(1);
            }
        }

        return result;

    }
}
