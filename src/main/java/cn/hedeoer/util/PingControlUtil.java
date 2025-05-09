package cn.hedeoer.util;

import cn.hedeoer.common.enmu.PingStatus;
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
     * 检查当前执行程序的用户是否拥有无密码的、完全的 root 权限。
     * <p>
     * "无密码的、完全的 root 权限" 指的是以下两种情况之一：
     * 1. 程序本身就是以 root 用户身份运行。
     * 2. 程序以普通用户身份运行，但该用户在 sudoers 配置中拥有类似
     *    `(ALL) NOPASSWD: ALL` 或 `(ALL : ALL) NOPASSWD: ALL` 的权限。
     * </p>
     *
     * @return 如果用户拥有无密码的、完全的 root 权限则返回true，否则返回false。
     */
    public static boolean hasAdminPrivileges() {
        // 1. 检查是否本身就是 root 用户
        if (isRoot()) {
            logger.info("Current user is root.");
            return true;
        }
        logger.info("Current user is not root. Checking for passwordless sudo privileges...");

        // 2. 检查 sudo -l 的输出，寻找 NOPASSWD: ALL 模式
        try {
            ProcessResult sudoLResult = new ProcessExecutor()
                    .command("sudo", "-nl") // 使用 -n 确保如果需要密码则立即失败，-l 列出权限
                    // 注意：`sudo -nl` 可能会先尝试一个需要root权限的测试命令，如果失败则回退到只列出权限
                    // 对于拥有 NOPASSWD: ALL 的用户，`sudo -nl` 应该能成功并列出权限。
                    // 如果用户没有 NOPASSWD: ALL，但有其他 sudo 权限（需要密码），
                    // `sudo -nl` 可能会因为 `-n` 而失败，退出码非0。
                    // 如果用户没有任何 sudo 权限，`sudo -l` (或 `-nl`) 也可能失败。
                    .readOutput(true)
                    .redirectErrorStream(true) // 将错误流也捕获到输出中，方便调试
                    .timeout(10, TimeUnit.SECONDS) // sudo -l 可能涉及网络查找或复杂解析
                    .execute();

            int exitCode = sudoLResult.getExitValue();
            String output = sudoLResult.outputUTF8();
            logger.debug("sudo -nl execution result - Exit Code: {}, Output:\n{}", exitCode, output);

            // 如果 `sudo -nl` 成功（通常退出码为0，但对于某些配置或情况，它可能在显示权限前就因-n而退出）
            // 我们更关注输出内容是否表明了 NOPASSWD: ALL
            // 对于 `(ALL) NOPASSWD: ALL` 的用户，`sudo -nl` 通常会成功列出权限，退出码为0。
            // 如果用户有sudo权限但需要密码，`sudo -nl` 退出码通常为1。
            // 如果用户完全没有sudo权限，`sudo -nl` 退出码也通常为1。

            if (exitCode == 0) { // `sudo -nl` 成功执行并列出了权限
                String[] lines = output.split("\\r?\\n");
                for (String line : lines) {
                    String trimmedLine = line.trim();
                    // 检查明确的 (ALL) NOPASSWD: ALL 或 (ALL : ALL) NOPASSWD: ALL 模式
                    // 正则表达式会更健壮，但这里用简化的startsWith和endsWith以及包含检查
                    // 模式1: (ALL) NOPASSWD: ALL
                    // 模式2: (ALL : ALL) NOPASSWD: ALL (或类似，允许中间有空格)
                    if (trimmedLine.matches("^\\s*\\(ALL\\s*(:\\s*ALL\\s*)?\\)\\s*NOPASSWD:\\s*ALL.*")) {
                        logger.info("Found passwordless full root access in 'sudo -nl' output: \"{}\"", trimmedLine);
                        return true;
                    }
                }
                logger.info("'sudo -nl' executed successfully, but no 'NOPASSWD: ALL' pattern found for all commands.");
                return false; // sudo -nl 成功，但没找到期望的无密码完全权限模式
            } else {
                // sudo -nl 执行失败 (exitCode != 0)，通常意味着用户没有 sudo 权限，
                // 或者有 sudo 权限但需要密码（因为 -n 选项）。
                // 这两种情况都不符合“无密码的、完全的 root 权限”。
                logger.info("'sudo -nl' command failed or indicated password requirement. Exit code: {}. Not considered passwordless full root.", exitCode);
                return false;
            }

        } catch (Exception e) {
            // 捕获执行 sudo -nl 过程中可能发生的任何异常（超时、命令不存在等）
            logger.error("Error executing or parsing 'sudo -nl' to check privileges: " + e.getMessage(), e);
            return false;
        }
    }
}