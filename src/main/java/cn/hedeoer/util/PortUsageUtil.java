package cn.hedeoer.util;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zeroturnaround.exec.ProcessExecutor;
import org.zeroturnaround.exec.ProcessResult;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Linux端口使用情况查询工具类
 */
public class PortUsageUtil {

    private static final Logger logger = LoggerFactory.getLogger(PortUsageUtil.class);

    /**
     * 查询指定端口的使用情况
     *
     * @param port 端口号
     * @return 端口使用情况列表
     * @throws IllegalArgumentException 端口范围无效时抛出
     */
    private static List<PortUsage> checkPortUsage(int port) {
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("Port must be between 1 and 65535");
        }

        List<PortUsage> result = Collections.emptyList();

        try {
            ProcessExecutor executor = new ProcessExecutor()
                    .command("lsof", "-w", "-i", ":" + port)
                    .readOutput(true)
                    .timeout(8, TimeUnit.SECONDS);

            try {
                ProcessResult processResult = executor.execute();
                String output = processResult.outputUTF8();
                result = parseOutput(output);
            } catch (TimeoutException e) {
                result = checkPortUsageAlternative(port);
            } catch (Exception e) {
                try {
                    ProcessResult sudoResult = executor
                            .command("sudo", "lsof", "-w", "-i", ":" + port)
                            .execute();
                    String output = sudoResult.outputUTF8();
                    result = parseOutput(output);
                } catch (TimeoutException te) {
                    result = checkPortUsageAlternative(port);
                }
            }
        } catch (Exception e) {
            logger.warn("Failed to check port usage for port {}: {}", port, e.getMessage());
        }

        return result;
    }
    /**
     * 备用方法：使用Java网络API或其他命令检查端口使用情况
     */
    private static List<PortUsage> checkPortUsageAlternative(int port) {
        List<PortUsage> result = new ArrayList<>();

        try {
            // 使用netstat命令作为备用，通常执行更快
            ProcessResult processResult = new ProcessExecutor()
                    .command("bash", "-c", "netstat -anp | grep :" + port)
                    .readOutput(true)
                    .timeout(3, TimeUnit.SECONDS)
                    .execute();

            String output = processResult.outputUTF8();
            result = parseNetstatOutput(output);
        } catch (Exception e) {
            // 最后一种方法：使用Java的Socket API测试端口是否被占用
            try (ServerSocket serverSocket = new ServerSocket(port)) {
                // 如果能正常绑定，说明端口未被占用
            } catch (IOException ioe) {
                // 端口被占用
                PortUsage usage = new PortUsage();
                usage.setCommand("未知程序");
                usage.setPid(-1);
                usage.setUser("未知");
                usage.setFd("未知");
                usage.setType("未知");
                usage.setDevice("未知");
                usage.setSizeOff("未知");
                usage.setNode("未知");
                usage.setName(":" + port);
                result.add(usage);
            }
        }

        return result;
    }

    /**
     * 解析netstat命令输出
     *
     * @param output netstat命令的输出字符串
     * @return 包含端口使用信息的列表
     */
    private static List<PortUsage> parseNetstatOutput(String output) {
        List<PortUsage> result = new ArrayList<>();
        if (output == null || output.trim().isEmpty()) {
            return result;
        }

        String[] lines = output.split("\\r?\\n");
        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("Proto")) {
                continue;
            }
            try {
                String[] parts = line.split("\\s+");
                if (parts.length < 6) continue;
                PortUsage usage = new PortUsage();
                usage.setCommand(parts.length >= 7 && parts[6].contains("/") ? parts[6].split("/", 2)[1] : "未知");
                usage.setPid(parts.length >= 7 && parts[6].contains("/") ? Integer.parseInt(parts[6].split("/", 2)[0]) : -1);
                usage.setUser("未知");
                usage.setFd("未知");
                usage.setType(parts[0]);
                usage.setDevice("未知");
                usage.setSizeOff("未知");
                usage.setNode(parts[5]);
                usage.setName(parts[3]);
                result.add(usage);
            } catch (Exception e) {
                logger.debug("Error parsing netstat output line: {}", line, e);
            }
        }
        return result;
    }


    /**
     * 获取监听端口的进程名字
     * 对于TCP端口，在同一IP地址上，一个端口在同一时刻只能被一个进程绑定监听
     * @param port 端口号
     * @return 进程名字,为null表示端口此时没有被进程监听
     */
    public static String getProcessCommandName(int port) {
        List<PortUsage> portUsages = checkPortUsage(port);
        return !portUsages.isEmpty() ? portUsages.get(0).getCommand() : null;
    }

    /**
     * 解析命令输出结果
     *
     * @param output 命令输出内容
     * @return 端口使用情况列表
     */
    private static List<PortUsage> parseOutput(String output) {
        List<PortUsage> usages = new ArrayList<>();

        String[] lines = output.split("\n");
        if (lines.length <= 1) {
            // 没有结果或只有表头
            return usages;
        }

        // 跳过表头行，从第二行开始解析
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.isEmpty()) continue;

            String[] parts = line.split("\\s+");

            if (parts.length >= 9) {
                PortUsage usage = new PortUsage();
                usage.setCommand(parts[0]);
                try {
                    usage.setPid(Integer.parseInt(parts[1]));
                } catch (NumberFormatException e) {
                    usage.setPid(-1);
                }
                usage.setUser(parts[2]);
                usage.setFd(parts[3]);
                usage.setType(parts[4]);
                usage.setDevice(parts[5]);
                usage.setSizeOff(parts[6]);
                usage.setNode(parts[7]);

                // 地址信息可能包含多个空格分隔的部分
                StringBuilder nameBuilder = new StringBuilder();
                for (int j = 8; j < parts.length; j++) {
                    if (j > 8) nameBuilder.append(" ");
                    nameBuilder.append(parts[j]);
                }
                usage.setName(nameBuilder.toString());

                usages.add(usage);
            }
        }

        return usages;
    }

    /**
     * 端口使用情况实体类
     */
    public static class PortUsage {
        private String command;  // 命令名称
        private int pid;         // 进程ID
        private String user;     // 用户
        private String fd;       // 文件描述符
        private String type;     // 类型
        private String device;   // 设备
        private String sizeOff;  // 大小/偏移
        private String node;     // 节点
        private String name;     // 网络地址

        // Getters and Setters
        public String getCommand() {
            return command;
        }

        public void setCommand(String command) {
            this.command = command;
        }

        public int getPid() {
            return pid;
        }

        public void setPid(int pid) {
            this.pid = pid;
        }

        public String getUser() {
            return user;
        }

        public void setUser(String user) {
            this.user = user;
        }

        public String getFd() {
            return fd;
        }

        public void setFd(String fd) {
            this.fd = fd;
        }

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

        public String getDevice() {
            return device;
        }

        public void setDevice(String device) {
            this.device = device;
        }

        public String getSizeOff() {
            return sizeOff;
        }

        public void setSizeOff(String sizeOff) {
            this.sizeOff = sizeOff;
        }

        public String getNode() {
            return node;
        }

        public void setNode(String node) {
            this.node = node;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        @Override
        public String toString() {
            return "PortUsage{" +
                    "command='" + command + '\'' +
                    ", pid=" + pid +
                    ", user='" + user + '\'' +
                    ", fd='" + fd + '\'' +
                    ", type='" + type + '\'' +
                    ", device='" + device + '\'' +
                    ", sizeOff='" + sizeOff + '\'' +
                    ", node='" + node + '\'' +
                    ", name='" + name + '\'' +
                    '}';
        }
    }
}
