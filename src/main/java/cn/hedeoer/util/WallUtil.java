package cn.hedeoer.util;

import cn.hedeoer.firewalld.exception.FirewallException;
import cn.hedeoer.firewalld.op.FirewallDRuleQuery;
import cn.hedeoer.pojo.FireWallType;
import cn.hedeoer.pojo.FirewallStatusInfo;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
import org.zeroturnaround.exec.ProcessExecutor;
import org.zeroturnaround.exec.ProcessResult;

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

    /**
     * 获取防火墙可用的区域(zone)名称列表
     *
     * 该方法会自动检测系统中启用的防火墙工具(firewalld/ufw)，并获取对应的zone列表：
     * 1. 如果系统未启用任何防火墙工具，返回空列表
     * 2. 如果同时启用了多个防火墙工具，优先使用firewalld
     * 3. 对于firewalld，通过DBus接口获取所有可用的zones
     * // todo 对应ufw的待实现
     * @return 区域名称列表。如果是firewalld，返回所有可用的zones；其他情况返回空列表
     * @throws RuntimeException 当与firewalld的DBus通信失败时抛出异常
     */
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


    // 检查命令是否存在
    private static boolean isCommandExist(String command) {
        try {
            String result = execGetLine("command", "-v", command);
            return result != null && !result.trim().isEmpty();
        } catch (Exception e) {
            return false;
        }
    }

    // 获取防火墙类型
    public static FireWallType  getFirewallType() {
        if (isCommandExist("firewalld")) {
            return FireWallType .FIREWALLD;
        }
        if (isCommandExist("ufw")) {
            return FireWallType.UFW;
        }
        return FireWallType.NONE;
    }

    // 获取防火墙状态
    public static String getFirewallStatus(FireWallType type) {
        try {
            if (type == FireWallType.FIREWALLD) {
                return execGetLine("systemctl", "is-active", "firewalld");
            }
            if (type == FireWallType.UFW) {
                // ufw status | grep -i status | awk '{print $2;}'
                String out = exec("ufw", "status");
                if (out == null) return "unknown";
                for (String line : out.split("\n")) {
                    if (line.toLowerCase().contains("status:")) {
                        return line.split(":", 2)[1].trim();
                    }
                }
                return "unknown";
            }
        } catch (Exception e) {
            return "unknown";
        }
        return "not installed";
    }

    // 获取防火墙版本
    public static String getFirewallVersion(FireWallType type) {
        try {
            if (type == FireWallType.FIREWALLD) {
                return execGetLine("firewall-cmd", "--version");
            }
            if (type == FireWallType.UFW) {
                // ufw version | grep -i ufw | awk '{print $2;}'
                String out = exec("ufw", "version");
                if (out != null) {
                    for (String line : out.split("\n")) {
                        if (line.toLowerCase().contains("ufw")) {
                            String[] arr = line.trim().split("\\s+");
                            if (arr.length >= 2) {
                                return arr[1];
                            }
                        }
                    }
                }
                return "unknown";
            }
        } catch (Exception e) {
            return "unknown";
        }
        return "not installed";
    }

    // 是否禁Ping
    public static boolean isPingDisabled(FireWallType type) {
        try {
            if (type == FireWallType.FIREWALLD) {
                // 主动查 zone
                String zone = execGetLine("firewall-cmd", "--get-default-zone");
                if (zone == null) zone = "public";
                String block = execGetLine("firewall-cmd", "--zone=" + zone, "--query-icmp-block=echo-request");
                return "yes".equalsIgnoreCase(block != null ? block.trim() : null);
            } else if (type == FireWallType.UFW) {
                // 查是否有deny icmp/deny到icmp echo的规则
                String status = exec("ufw", "status", "verbose");
                // 典型 deny的行： "Anywhere DENY IN icmp"
                return status != null && status.toLowerCase().contains("deny") && status.toLowerCase().contains("icmp");
            }
        } catch (Exception e) {
            return false;
        }
        return false;
    }

    // zt-exec 执行并返回首行
    private static String execGetLine(String... cmd) throws Exception {
        // 建议统一指定环境变量，防止乱码
        ProcessResult result = new ProcessExecutor()
                .command(cmd)
                .readOutput(true)
                .exitValues(0)
                .environment("LANG", "en_US.UTF-8") // 增加这行
                .timeout(5000, TimeUnit.SECONDS)
                .execute();
        String out = result.outputString().trim();
        return out.isEmpty() ? null : out.split("\n")[0].trim();
    }

    // 执行并返回完整输出
    private static String exec(String... cmd) throws Exception {
        ProcessResult result = new ProcessExecutor()
                .command(cmd)
                .readOutput(true)
                .exitValues(0)
                .environment("LANG", "en_US.UTF-8") // 增加这行
                .timeout(5000, TimeUnit.SECONDS)
                .execute();
        return result.outputString().trim();
    }

    public static FirewallStatusInfo getFirewallStatusInfo(){
        FireWallType type = getFirewallType();
        String agentId = AgentIdUtil.loadOrCreateUUID();
        return FirewallStatusInfo.builder()
                .agentId(agentId)
                .firewallType(type.toString())
                .version(getFirewallVersion(type))
                .status(getFirewallStatus(type))
                .pingDisabled(isPingDisabled(type))
                .timestamp(System.currentTimeMillis() / 1000)
                .build();
    }

    public static void main(String[] args) {
        FireWallType type = getFirewallType();
        System.out.println("防火墙类型: " + type);
        System.out.println("运行状态: " + getFirewallStatus(type));
        System.out.println("版本: " + getFirewallVersion(type));
        System.out.println("是否禁ping: " + isPingDisabled(type));

        System.out.println(getFirewallStatusInfo());
    }

}
