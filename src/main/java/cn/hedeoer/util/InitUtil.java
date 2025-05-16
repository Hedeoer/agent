package cn.hedeoer.util;

import cn.hedeoer.common.enmu.FireWallType;
import cn.hedeoer.firewall.ufw.UfwRuleConverterWithYourParser;
import cn.hedeoer.ssh.SimpleSshServerWithPublicKeyAuth;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.TimeoutException;

public class InitUtil {

    private static final Logger logger = LoggerFactory.getLogger(InitUtil.class);

    public static Boolean init() {

        boolean result = true;

        logger.info("当前节点唯一标识：>>>>>>>>>>>>>>>{}",AgentIdUtil.loadOrCreateUUID());

        // 系统用户权限
        if (!PingControlUtil.hasAdminPrivileges()) {
            logger.error("程序执行用户权限异常，要求具有免密管理员权限用户执行程序");
            System.exit(1);

        }

        // 启动apache mina sshd服务端
        boolean runningInDocker = Boolean.parseBoolean(System.getenv("RUNNING_IN_DOCKER"));
        Integer sshServerPort = null;
        String sshPublicKey = null;
        // 从环境变量中读取配置
        sshPublicKey = System.getenv("SSH_PUBLIC_KEY");
        sshServerPort = Integer.parseInt(System.getenv("SSH_SERVER_PORT"));
        // 如果是非docker运行的方式并且环境变量中没有需要的环境变量设置，则从yaml配置中读取
        if (!runningInDocker && sshPublicKey.isEmpty()) {
            Map<String, Object> sshConfigMap = YamlUtil.getYamlConfig("ssh");
            sshServerPort = (Integer)sshConfigMap.get("ssh_server_port");
            sshPublicKey = (String)sshConfigMap.get("ssh_public_key");
        }

        if (sshServerPort == null || sshPublicKey == null) {
            logger.error("ssh所需的配置项: ssh_server_port:{}, ssh_public_key:{} 异常",sshServerPort,sshPublicKey);
            System.exit(1);

        }
        SimpleSshServerWithPublicKeyAuth sshServer = new SimpleSshServerWithPublicKeyAuth(sshServerPort,sshPublicKey);
        if (!sshServer.startSshServer()) {
            logger.error("无法启动ssh服务");
            System.exit(1);
        }

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
