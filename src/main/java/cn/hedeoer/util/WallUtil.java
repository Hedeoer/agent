package cn.hedeoer.util;

import cn.hedeoer.common.enmu.FireWallStatus;
import cn.hedeoer.common.enmu.FirewallOperationType;
import cn.hedeoer.firewalld.firewalld.exception.FirewallException;
import cn.hedeoer.firewalld.firewalld.op.FirewallDRuleQuery;
import cn.hedeoer.common.enmu.FireWallType;
import cn.hedeoer.pojo.FirewallStatusInfo;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zeroturnaround.exec.ProcessExecutor;
import org.zeroturnaround.exec.ProcessResult;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class WallUtil {
    private static final Logger logger = LoggerFactory.getLogger(WallUtil.class);
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


    /**
     * 检查命令是否存在
     * @param command 要检查的命令
     * @return 命令是否存在
     */
    private static boolean isCommandExist(String command) {
        try {
            // 使用 "which" 命令检查，这在大多数 Linux 发行版中都可用
            String result = execGetLine("sudo","which", command);
            if (result != null && !result.trim().isEmpty()) {
                return true;
            }

            // 如果 which 命令失败，尝试使用 bash -c 执行 command -v
            result = execGetLine("bash", "-c", "command -v " + command);
            return result != null && !result.trim().isEmpty();
        } catch (Exception e) {
            // 如果上述方法都失败，检查常见路径
            return checkCommonPaths(command);
        }
    }

    /**
     * 检查命令在常见路径中是否存在
     * @param command 要检查的命令
     * @return 命令是否存在
     */
    private static boolean checkCommonPaths(String command) {
        String[] commonPaths = {
                "/usr/sbin/" + command,
                "/sbin/" + command,
                "/usr/bin/" + command,
                "/bin/" + command
        };

        for (String path : commonPaths) {
            File file = new File(path);
            if (file.exists() && file.canExecute()) {
                return true;
            }
        }
        return false;
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
    /**
     * 获取指定类型防火墙的当前状态
     *
     * <p>此方法通过执行系统命令检查防火墙的运行状态。对于 firewalld，使用 systemctl 命令；
     * 对于 ufw，解析 ufw status 命令的输出。</p>
     *
     * <p>可能的返回值:</p>
     * <ul>
     *   <li>对于 firewalld: "active", "inactive", "unknown", "not installed"</li>
     *   <li>对于 ufw: "active", "inactive", "enabled", "disabled", "unknown", "not installed"</li>
     * </ul>
     *
     * @param type 要检查的防火墙类型
     * @return 防火墙的状态字符串
     */
    public static FireWallStatus getFirewallStatus(FireWallType type) {
        String statusText = "unknown";
        try {
            if (type == FireWallType.FIREWALLD) {
                statusText =  execGetLine("systemctl", "is-active", "firewalld");
            }else if (type == FireWallType.UFW) {
                // ufw status | grep -i status | awk '{print $2;}'
                String out = exec("ufw", "status");
                if (out == null) statusText = "unknown";
                for (String line : out.split("\n")) {
                    if (line.toLowerCase().contains("status:")) {
                        statusText =  line.split(":", 2)[1].trim();
                    }
                }
                statusText = "unknown";
            }else{
                statusText =  "not installed";
            }
        } catch (Exception e) {
            statusText = "unknown";
        }
        return FireWallStatus.fromString(statusText);
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



    // zt-exec 执行并返回首行
    /**
     * 执行命令并返回首行输出
     * @param cmd 要执行的命令及参数
     * @return 命令输出的第一行，如果没有输出则返回null
     * @throws Exception 执行过程中的异常
     */
    private static String execGetLine(String... cmd)  {
        try {
            ProcessResult result = new ProcessExecutor()
                    .command(cmd)
                    .readOutput(true)
                    .exitValues(0, 1) // 允许退出代码为0或1，因为某些命令在未找到时返回1
                    .environment("LANG", "en_US.UTF-8")
                    .timeout(10, TimeUnit.SECONDS) // 缩短超时时间到10秒
                    .execute();

            String out = result.outputString().trim();
            return out.isEmpty() ? null : out.split("\n")[0].trim();
        } catch (Exception e) {
            // 如果是超时或其他预期内的异常，直接返回null
            return null;
        }
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
                .firewallType(type)
                .version(getFirewallVersion(type))
                .status(getFirewallStatus(type))
                .pingDisabled(PingControlUtil.getCurrentPingStatus())
                .timestamp(System.currentTimeMillis() / 1000)
                .build();
    }



    /**
     * 对系统防火墙进行简要操作，启动，停止，重启
     * @param fireWallStatusOpType  fireWallStatusOpType
     * @return 操作成功返回true，否则返回false
     */
    public static Boolean operateFireWall(FirewallOperationType fireWallStatusOpType) {
        FireWallType firewallType = getFirewallType();
        String command = null;

        try {
            if (FireWallType.FIREWALLD.equals(firewallType)) {
                // 处理 firewalld 防火墙
                switch (fireWallStatusOpType) {
                    case START:
                        command = "sudo systemctl start firewalld";
                        break;
                    case STOP:
                        command = "sudo systemctl stop firewalld";
                        break;
                    case RESTART:
                        command = "sudo systemctl restart firewalld";
                        break;
                    default:
                        return false;
                }

                int exitValue = new ProcessExecutor()
                        .command("bash", "-c", command)
                        .exitValueNormal()
                        .execute()
                        .getExitValue();

                if (exitValue != 0) {
                    logger.error("Failed to execute command: {}, exit value: {}", command, exitValue);
                    return false;
                }

            } else if (FireWallType.UFW.equals(firewallType)) {
                // 处理 UFW 防火墙
                switch (fireWallStatusOpType) {
                    case START:
                        command = "sudo ufw enable";
                        // UFW 可能会要求交互确认，添加 --force 参数避免交互
                        command = "echo y | " + command + " --force";
                        break;
                    case STOP:
                        command = "sudo ufw disable";
                        break;
                    case RESTART:
                        command = "sudo ufw disable && sudo ufw enable";
                        // UFW 可能会要求交互确认，添加 --force 参数避免交互
                        command = "echo y | " + command + " --force";
                        break;
                    default:
                        return false;
                }

                int exitValue = new ProcessExecutor()
                        .command("bash", "-c", command)
                        .exitValueNormal()
                        .execute()
                        .getExitValue();

                if (exitValue != 0) {
                    logger.error("Failed to execute command: {}, exit value: {}", command, exitValue);
                    return false;
                }

            } else {
                // 不支持的防火墙类型
                logger.error("Unsupported firewall type: {}", firewallType);
                return false;
            }

            // 添加延时检测机制
            return waitForFirewallStatus(firewallType, fireWallStatusOpType, 5, 1000);

        } catch (Exception e) {
            logger.error("Failed to operate firewall: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * 等待防火墙状态变更并检测结果
     *
     * @param firewallType 防火墙类型
     * @param opType 操作类型
     * @param maxAttempts 最大尝试次数
     * @param delayMs 每次尝试之间的延迟(毫秒)
     * @return 如果防火墙状态符合预期则返回true，否则返回false
     */
    private static boolean waitForFirewallStatus(FireWallType firewallType, FirewallOperationType opType,
                                                 int maxAttempts, long delayMs) {
        logger.info("Waiting for firewall {} operation to complete...", opType.name());

        // 确定期望的状态
        boolean expectedRunning = opType != FirewallOperationType.STOP;

        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                // 延迟检测
                Thread.sleep(delayMs);

                // 检查当前状态
                boolean isRunning = FireWallStatus.ACTIVE.equals(getFirewallStatus(firewallType));
                logger.debug("Firewall status check attempt {}/{}: expected={}, actual={}",
                        attempt, maxAttempts, expectedRunning, isRunning);

                if (isRunning == expectedRunning) {
                    logger.info("Firewall {} operation completed successfully", opType.name());
                    return true;
                }

                // 如果是最后一次尝试，记录警告
                if (attempt == maxAttempts) {
                    logger.warn("Firewall status did not change to expected state after {} attempts", maxAttempts);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logger.warn("Interrupted while waiting for firewall status change", e);
                return false;
            } catch (Exception e) {
                logger.error("Error checking firewall status: {}", e.getMessage(), e);
                // 继续尝试下一次检测
            }
        }

        return false;
    }


    public static void main(String[] args) {
//        FireWallType type = getFirewallType();
//        System.out.println("防火墙类型: " + type);
//        System.out.println("运行状态: " + getFirewallStatus(type));
//        System.out.println("版本: " + getFirewallVersion(type));
//        System.out.println("是否禁ping: " + pingStatus());
//
//        System.out.println(getFirewallStatusInfo());
//
//        System.out.println(operateFireWall(FirewallOperationType.START));
//
//        System.out.println(PingControlUtil.pingStatus());
//        System.out.println(PingControlUtil.getCurrentPingStatus());

        System.out.println(PingControlUtil.hasAdminPrivileges());
        System.out.println(PingControlUtil.enablePing());
    }
}
