package cn.hedeoer.util;

import cn.hedeoer.firewalld.exception.FirewallException;
import cn.hedeoer.pojo.FireWallType;
import org.zeroturnaround.exec.ProcessExecutor;

import java.io.IOException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class WallUtil {
    /*
    * 识别操作系统使用的防火墙工具
    * 针对centos，debian系统
    * 只对firewall，ufw处理
    * */

    public static void getWallType(){
        if (OperateSystemUtil.isLinux()) {
            // 判断操作系统具体类型， centos， debian..

            // 判断是否使用了 ufw 或者 firewall工具，且是否同时启用多种防火墙工具

            // 没有使用或者没有启用如何设置？
        }
    }

    /**
     * 重新加载防火墙配置
     * @param fireWallType
     */
    public static void reloadFirewall(FireWallType fireWallType) throws FirewallException {
        try {
            new ProcessExecutor()
                    .command("/bin/bash", "-c", "firewall-cmd --reload")
                    .timeout(30, TimeUnit.SECONDS)
                    .execute();
        } catch (IOException | InterruptedException | TimeoutException e) {
            throw new FirewallException("Failed to reload firewall: " + e.getMessage(), e);
        }
    }

    /**
     * 检查端口和协议是否合法
     */
    public static boolean isIllegal(String port, String protocol) {
        // 协议只允许 tcp 或 udp
        if (protocol == null || (!protocol.equalsIgnoreCase("tcp") && !protocol.equalsIgnoreCase("udp"))) {
            return true;
        }

        // 端口检查
        if (port == null || port.isEmpty()) {
            return true;
        }

        // 检查端口格式 (单个端口或端口范围)
        if (port.contains("-")) {
            String[] range = port.split("-");
            if (range.length != 2) {
                return true;
            }
            try {
                int start = Integer.parseInt(range[0]);
                int end = Integer.parseInt(range[1]);
                return start < 1 || end > 65535 || start > end;
            } catch (NumberFormatException e) {
                return true;
            }
        } else {
            try {
                int portNum = Integer.parseInt(port);
                return portNum < 1 || portNum > 65535;
            } catch (NumberFormatException e) {
                return true;
            }
        }
    }

}
