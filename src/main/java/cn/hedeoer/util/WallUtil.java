package cn.hedeoer.util;

import cn.hedeoer.firewalld.exception.FirewallException;
import cn.hedeoer.firewalld.op.FirewallDRuleQuery;
import cn.hedeoer.pojo.FireWallType;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
import org.zeroturnaround.exec.ProcessExecutor;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class WallUtil {
    private static final String FIREWALLD_PATH = "/org/fedoraproject/FirewallD1";
    private static final String FIREWALLD_BUS_NAME = "org.fedoraproject.FirewallD1";
    /*
     * 识别操作系统使用的防火墙工具
     * 针对centos，debian系统
     * 只对firewall，ufw处理
     * */

    public static void getWallType() {
        if (OperateSystemUtil.isLinux()) {
            // 判断操作系统具体类型， centos， debian..

            // 判断是否使用了 ufw 或者 firewall工具，且是否同时启用多种防火墙工具

            // 没有使用或者没有启用如何设置？
        }
    }

    /**
     * 重新加载防火墙配置
     *
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

    public static List<String> getZoneNames() {
        List<String> zoneNames = new ArrayList<>();
        // 获取系统目前启用的防火墙工具
        List<String> enabledFirewalls = FirewallDetector.getEnabledFirewalls();

        // 如果没有启用任何防火墙工具，返回空列表
        if (enabledFirewalls.isEmpty()) {
            return zoneNames;
        }

        // 如果同时启用ufw和firewalld，默认使用firewalld
        FireWallType willUseFireWallType;
        if (enabledFirewalls.size() > 1) {
            willUseFireWallType = FireWallType.FIREWALLD;
        } else {
            willUseFireWallType = FireWallType.valueOf(enabledFirewalls.get(0).toUpperCase());
        }

        // 如果启用的防火墙工具为firewalld
        if (FireWallType.FIREWALLD.equals(willUseFireWallType)) {
            try {
                // 获取DBus连接
                DBusConnection connection = FirewallDRuleQuery.getDBusConnection();

                // 获取zone接口
                FirewallDRuleQuery.FirewallDZoneInterface zoneInterface = connection.getRemoteObject(
                        FIREWALLD_BUS_NAME,
                        FIREWALLD_PATH,
                        FirewallDRuleQuery.FirewallDZoneInterface.class);

                // 获取所有zones
                String[] zones = zoneInterface.getZones();
                return zones != null ? Arrays.asList(zones) : new ArrayList<String>();
            } catch (DBusException e) {
                try {
                    throw new FirewallException("Failed to get zone names: " + e.getMessage(), e);
                } catch (FirewallException ex) {
                    throw new RuntimeException(ex);
                }
            }
        }

        return zoneNames;

    }

}
