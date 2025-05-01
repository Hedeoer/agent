package cn.hedeoer.util;

import cn.hedeoer.common.PingStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zeroturnaround.exec.ProcessExecutor;
import org.zeroturnaround.exec.ProcessResult;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Linux系统Ping命令控制工具类
 */
public class PingControlUtil {
    private static final Logger logger = LoggerFactory.getLogger(PingControlUtil.class);
    private static final String SYSCTL_CONF_PATH = "/etc/sysctl.conf";
    private static final String PING_PARAM = "net.ipv4.icmp_echo_ignore_all";
    private static final String PING_PARAM_PATTERN = PING_PARAM + "=";



    /**
     * 检查当前系统的Ping状态
     *
     * @return Ping状态枚举值
     */
    public static PingStatus pingStatus() {
        // 检查文件是否存在
        File sysctlFile = new File(SYSCTL_CONF_PATH);
        if (!sysctlFile.exists()) {
            return PingStatus.STATUS_NONE;
        }

        try {
            // 使用 zt-exec 执行命令，但允许退出码 0 和 1
            // 退出码 0 表示找到匹配，1 表示没找到匹配
            ProcessResult result = new ProcessExecutor()
                    .command("grep", PING_PARAM_PATTERN, SYSCTL_CONF_PATH)
                    .readOutput(true)
                    .exitValues(0, 1)  // 允许退出码 0 和 1
                    .timeout(5, TimeUnit.SECONDS)
                    .execute();

            // 检查退出码和输出
            int exitCode = result.getExitValue();
            String output = result.outputUTF8();

            if (exitCode == 0 && output != null && !output.isEmpty() && output.trim().endsWith("=1")) {
                return PingStatus.STATUS_ENABLE;
            }

            // 如果 grep 没找到匹配项(退出码 1)或找到但不是设置为 1，则认为 ping 是允许的
            return PingStatus.STATUS_DISABLE;
        } catch (Exception e) {
            // 处理其他可能的异常，如超时
            logger.warn("Error checking ping status: " + e.getMessage(), e);
            return PingStatus.STATUS_DISABLE;
        }
    }

    /**
     * 获取当前实际生效的Ping状态（从/proc文件系统读取）
     *
     * @return Ping状态枚举值
     */
    public static PingStatus getCurrentPingStatus() {
        try {
            ProcessResult result = new ProcessExecutor()
                    .command("cat", "/proc/sys/net/ipv4/icmp_echo_ignore_all")
                    .readOutput(true)
                    .exitValue(0)
                    .timeout(5, TimeUnit.SECONDS)
                    .execute();

            String output = result.outputUTF8().trim();
            if ("1".equals(output)) {
                return PingStatus.STATUS_ENABLE; // 禁用ping
            } else if ("0".equals(output)) {
                return PingStatus.STATUS_DISABLE; // 启用ping
            } else {
                logger.warn("Unexpected value for icmp_echo_ignore_all: {}", output);
                return PingStatus.STATUS_NONE;
            }
        } catch (Exception e) {
            logger.error("Error getting current ping status: " + e.getMessage(), e);
            return PingStatus.STATUS_NONE;
        }
    }

    /**
     * 启用或禁用Ping
     *
     * @param disable true表示禁用Ping，false表示启用Ping
     * @return 操作是否成功
     */
    public static boolean setPingStatus(boolean disable) {
        // 检查权限
        if (!hasAdminPrivileges()) {
            logger.error("Administrative privileges required to change ping status");
            return false;
        }

        // 设置值：1表示禁用ping，0表示启用ping
        String value = disable ? "1" : "0";
        String paramSetting = PING_PARAM + "=" + value;

        try {
            // 1. 立即生效的临时设置
            boolean immediateResult = setImmediatePingStatus(value);
            if (!immediateResult) {
                logger.error("Failed to set immediate ping status to {}", disable ? "disabled" : "enabled");
                return false;
            }

            // 2. 持久化设置到sysctl.conf
            boolean persistentResult = updateSysctlConf(paramSetting);
            if (!persistentResult) {
                logger.warn("Failed to persist ping status to {}, but immediate setting was successful",
                        disable ? "disabled" : "enabled");
                // 即使持久化失败，临时设置成功也返回true，但记录警告
                return true;
            }

            // 3. 应用sysctl配置以确保设置生效
            boolean applyResult = applySysctlSettings();
            if (!applyResult) {
                logger.warn("Failed to apply sysctl settings, but changes were made to configuration file");
                // 配置文件已更新，临时设置也成功，所以仍然返回true
                return true;
            }

            logger.info("Successfully {} ping and persisted the setting", disable ? "disabled" : "enabled");
            return true;
        } catch (Exception e) {
            logger.error("Error setting ping status to {}: {}",
                    disable ? "disabled" : "enabled", e.getMessage(), e);
            return false;
        }
    }

    /**
     * 禁用Ping（禁止外部主机ping本机）
     *
     * @return 操作是否成功
     */
    public static boolean disablePing() {
        return setPingStatus(true);
    }

    /**
     * 启用Ping（允许外部主机ping本机）
     *
     * @return 操作是否成功
     */
    public static boolean enablePing() {
        return setPingStatus(false);
    }

    /**
     * 立即设置Ping状态（临时生效，重启后失效）
     *
     * @param value "1"表示禁用ping，"0"表示启用ping
     * @return 操作是否成功
     */
    private static boolean setImmediatePingStatus(String value) {
        try {
            List<String> command = new ArrayList<>();
            if (!isRoot()) {
                command.add("sudo");
            }
            command.add("sysctl");
            command.add("-w");
            command.add(PING_PARAM + "=" + value);

            ProcessResult result = new ProcessExecutor()
                    .command(command)
                    .readOutput(true)
                    .exitValue(0)
                    .timeout(10, TimeUnit.SECONDS)
                    .execute();

            String output = result.outputUTF8();
            return output != null && output.contains(PING_PARAM) && output.contains(value);
        } catch (Exception e) {
            logger.error("Error setting immediate ping status: " + e.getMessage(), e);
            return false;
        }
    }

    /**
     * 更新sysctl.conf配置文件
     *
     * @param paramSetting 参数设置，格式为"net.ipv4.icmp_echo_ignore_all=值"
     * @return 操作是否成功
     */
    private static boolean updateSysctlConf(String paramSetting) {
        Path sysctlPath = Paths.get(SYSCTL_CONF_PATH);

        // 检查文件是否存在
        if (!Files.exists(sysctlPath)) {
            try {
                // 使用管理员权限创建文件
                List<String> command = new ArrayList<>();
                if (!isRoot()) {
                    command.add("sudo");
                }
                command.add("sh");
                command.add("-c");
                command.add("echo '" + paramSetting + "' > " + SYSCTL_CONF_PATH);

                ProcessResult result = new ProcessExecutor()
                        .command(command)
                        .exitValue(0)
                        .timeout(10, TimeUnit.SECONDS)
                        .execute();

                return result.getExitValue() == 0;
            } catch (Exception e) {
                logger.error("Failed to create sysctl.conf file: " + e.getMessage(), e);
                return false;
            }
        }

        try {
            // 读取现有文件内容
            List<String> lines;
            try {
                lines = Files.readAllLines(sysctlPath);
            } catch (IOException e) {
                // 如果无法直接读取，使用sudo cat读取
                ProcessResult result = new ProcessExecutor()
                        .command(isRoot() ? new String[]{"cat", SYSCTL_CONF_PATH} :
                                new String[]{"sudo", "cat", SYSCTL_CONF_PATH})
                        .readOutput(true)
                        .exitValue(0)
                        .timeout(10, TimeUnit.SECONDS)
                        .execute();

                String content = result.outputUTF8();
                lines = new ArrayList<>();
                for (String line : content.split("\n")) {
                    lines.add(line);
                }
            }

            boolean paramFound = false;
            StringBuilder newContent = new StringBuilder();

            // 检查参数是否已存在，如果存在则更新
            for (String line : lines) {
                String trimmedLine = line.trim();
                if (trimmedLine.startsWith(PING_PARAM_PATTERN) ||
                        trimmedLine.startsWith("#" + PING_PARAM_PATTERN)) {
                    newContent.append(paramSetting).append("\n");
                    paramFound = true;
                } else {
                    newContent.append(line).append("\n");
                }
            }

            // 如果参数不存在，则添加到文件末尾
            if (!paramFound) {
                newContent.append(paramSetting).append("\n");
            }

            // 使用管理员权限写回文件
            List<String> command = new ArrayList<>();
            if (!isRoot()) {
                command.add("sudo");
            }
            command.add("sh");
            command.add("-c");
            command.add("cat > " + SYSCTL_CONF_PATH);

            ProcessResult result = new ProcessExecutor()
                    .command(command)
                    .redirectInput(new ByteArrayInputStream(newContent.toString().getBytes()))
                    .exitValue(0)
                    .timeout(10, TimeUnit.SECONDS)
                    .execute();

            return result.getExitValue() == 0;
        } catch (Exception e) {
            logger.error("Error updating sysctl.conf: " + e.getMessage(), e);
            return false;
        }
    }

    /**
     * 应用sysctl设置
     *
     * @return 操作是否成功
     */
    private static boolean applySysctlSettings() {
        try {
            List<String> command = new ArrayList<>();
            if (!isRoot()) {
                command.add("sudo");
            }
            command.add("sysctl");
            command.add("-p");

            ProcessResult result = new ProcessExecutor()
                    .command(command)
                    .readOutput(true)
                    .exitValue(0)
                    .timeout(10, TimeUnit.SECONDS)
                    .execute();

            return result.getExitValue() == 0;
        } catch (Exception e) {
            logger.error("Error applying sysctl settings: " + e.getMessage(), e);
            return false;
        }
    }

    /**
     * 检查当前用户是否为root
     *
     * @return 是否为root用户
     */
    private static boolean isRoot() {
        try {
            ProcessResult result = new ProcessExecutor()
                    .command("id", "-u")
                    .readOutput(true)
                    .exitValue(0)
                    .execute();

            String output = result.outputUTF8().trim();
            return "0".equals(output);
        } catch (Exception e) {
            logger.error("Error checking if user is root: " + e.getMessage(), e);
            return false;
        }
    }

    /**
     * 检查是否有管理员权限（root或sudo）
     *
     * @return 是否有管理员权限
     */
    public static boolean hasAdminPrivileges() {
        // 首先检查是否为root用户
        if (isRoot()) {
            return true;
        }

        // 然后检查是否有sudo权限执行sysctl命令
        try {
            ProcessResult result = new ProcessExecutor()
                    .command("sudo", "-n", "sysctl", "-n", "kernel.hostname")
                    .readOutput(true)
                    .exitValues(0, 1)  // 允许退出码0和1
                    .timeout(5, TimeUnit.SECONDS)
                    .execute();

            return result.getExitValue() == 0;
        } catch (Exception e) {
            logger.debug("User does not have passwordless sudo access: " + e.getMessage());

            // 尝试检查用户是否在sudoers列表中
            try {
                ProcessResult result = new ProcessExecutor()
                        .command("sudo", "-l")
                        .readOutput(true)
                        .exitValues(0, 1)
                        .timeout(5, TimeUnit.SECONDS)
                        .execute();

                String output = result.outputUTF8();
                return result.getExitValue() == 0 &&
                        (output.contains("(ALL)") || output.contains("sysctl"));
            } catch (Exception ex) {
                logger.error("Error checking sudo privileges: " + ex.getMessage(), ex);
                return false;
            }
        }
    }
}