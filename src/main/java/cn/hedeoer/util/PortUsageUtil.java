package cn.hedeoer.util;

import org.zeroturnaround.exec.ProcessExecutor;
import org.zeroturnaround.exec.ProcessResult;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Stream;

/**
 * Linux端口使用情况查询工具类
 */
public class PortUsageUtil {

    /**
     * 查询指定端口的使用情况
     *
     * @param port 端口号
     * @return 端口使用情况列表
     * @throws IOException          执行命令时发生IO异常
     * @throws InterruptedException 执行被中断
     * @throws TimeoutException     执行超时
     */
    private static List<PortUsage> checkPortUsage(int port) {
        try {
            // 校验端口范围
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("Port must be between 1 and 65535");
            }

            // 执行lsof命令
            // -w表示获取完整进程名字
            ProcessResult result = new ProcessExecutor()
                    .command("sudo", "lsof", "-w", "-i", ":" + port)
                    .readOutput(true)
                    .timeout(5, TimeUnit.SECONDS)
                    .execute();

            // 解析输出结果
            String output = result.outputUTF8();
            return parseOutput(output);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } catch (TimeoutException e) {
            throw new RuntimeException(e);
        }
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
