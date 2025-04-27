package cn.hedeoer.util;

import java.util.*;
import java.util.stream.Collectors;

import oshi.SystemInfo;
import oshi.software.os.InternetProtocolStats;
import oshi.software.os.OSProcess;
import oshi.software.os.OperatingSystem;
import oshi.software.os.InternetProtocolStats.IPConnection;

/**
 * 端口监控工具类
 * 基于oshi-core库查询指定端口范围的使用情况
 */
public class PortMonitorUtils {

    /**
     * 端口信息实体类
     */
    public static class PortInfo {
        private int portNumber;          // 端口号
        private String processName;      // 进程名
        private int processId;           // 进程ID
        private String commandLine;      // 完整命令行
        private String listenAddress;    // 监听地址

        public PortInfo(int portNumber, String processName, int processId, String commandLine, String listenAddress) {
            this.portNumber = portNumber;
            this.processName = processName;
            this.processId = processId;
            this.commandLine = commandLine;
            this.listenAddress = listenAddress;
        }

        // Getters
        public int getPortNumber() { return portNumber; }
        public String getProcessName() { return processName; }
        public int getProcessId() { return processId; }
        public String getCommandLine() { return commandLine; }
        public String getListenAddress() { return listenAddress; }

        // Helper method to determine information completeness
        private int getInfoCompletenessScore() {
            int score = 0;
            if (processName != null && !processName.isEmpty()) score += 2;
            if (commandLine != null && !commandLine.isEmpty()) score += 2;
            if (listenAddress != null && !listenAddress.equals("unknown")) score += 1;
            if (processId > 0) score += 1;
            return score;
        }

        @Override
        public String toString() {
            return "PortInfo{" +
                    "portNumber=" + portNumber +
                    ", processName='" + processName + '\'' +
                    ", processId=" + processId +
                    ", commandLine='" + commandLine + '\'' +
                    ", listenAddress='" + listenAddress + '\'' +
                    '}';
        }
    }

    /**
     * 获取指定端口范围内的所有端口使用情况。
     * <p>
     * 此方法通过 OSHI 库查询指定端口范围内的 TCP 和 UDP 连接，收集每个端口的占用情况，
     * 包括端口号、关联进程的名称、进程 ID、命令行以及监听的 IP 地址。
     * 对于每个端口，仅保留信息最完整的一条记录（基于 PortInfo 的信息完整度评分）。
     * </p>
     *
     * @param startPort 起始端口号（包含）。必须为非负数且不大于 endPort。
     * @param endPort 结束端口号（包含）。必须为非负数且不超过 65535。
     * @return 返回一个 PortInfo 列表，包含范围内所有被占用的端口信息。
     *         如果没有端口被占用或范围无效，返回空列表。
     *         <p>PortInfo 对象各属性的可能取值如下：</p>
     *         <ul>
     *           <li><b>portNumber</b>: 整数，范围 [startPort, endPort]，例如 80、6379。</li>
     *           <li><b>processName</b>: 字符串，进程名称（例如 "java"、"nginx"），可能为 ""（空字符串）或 null（取决于 oshi 实现）。</li>
     *           <li><b>processId</b>: 整数，通常为正数（例如 1234），表示进程 ID；可能为 0（无关联进程，但通常不会创建 PortInfo）。</li>
     *           <li><b>commandLine</b>: 字符串，进程的命令行（例如 "/usr/bin/java -jar app.jar"），可能为 "" 或 null（取决于 oshi 实现）。</li>
     *           <li><b>listenAddress</b>: 字符串，格式化的 IP 地址（例如 IPv4: "192.168.1.1"，IPv6: "2001:0db8:85a3:0000:0000:8a2e:0370:7334"），或 "unknown"（地址不可用），或十六进制字符串（未知格式，例如 "0a000001"）。</li>
     *         </ul>
     * @throws IllegalArgumentException 如果 startPort 大于 endPort。
     */
    public static List<PortInfo> getPortsUsage(int startPort, int endPort) {
        if (startPort > endPort) {
            throw new IllegalArgumentException("起始端口必须小于或等于结束端口");
        }

        SystemInfo systemInfo = new SystemInfo();
        OperatingSystem os = systemInfo.getOperatingSystem();
        InternetProtocolStats ipStats = os.getInternetProtocolStats();

        // 获取所有TCP和UDP连接
        List<IPConnection> allConnections = new ArrayList<>();
        allConnections.addAll(ipStats.getConnections());

        // Map to store the best PortInfo for each port
        Map<Integer, PortInfo> portInfoMap = new HashMap<>();

        for (IPConnection conn : allConnections) {
            int localPort = conn.getLocalPort();

            if (localPort >= startPort && localPort <= endPort) {
                int pid = conn.getowningProcessId();
                String listenAddress = formatAddress(conn.getLocalAddress());
                OSProcess process = os.getProcess(pid);

                if (process != null) {
                    String processName = process.getName();
                    String commandLine = process.getCommandLine();
                    PortInfo newInfo = new PortInfo(localPort, processName, pid, commandLine, listenAddress);

                    // Update if no existing info or new info is more complete
                    portInfoMap.compute(localPort, (port, existingInfo) -> {
                        if (existingInfo == null) {
                            return newInfo;
                        }
                        return newInfo.getInfoCompletenessScore() > existingInfo.getInfoCompletenessScore()
                                ? newInfo : existingInfo;
                    });
                }
            }
        }

        return new ArrayList<>(portInfoMap.values());
    }

    /**
     * 获取指定端口列表的端口使用情况。
     * <p>
     * 此方法接收一个端口号字符串列表，查询这些端口的占用情况。
     * 它通过将字符串端口转换为整数、验证有效性，然后调用基于范围的 getPortsUsage 方法
     * 获取所有相关端口信息，最后过滤出指定端口的记录。
     * 每个端口仅保留信息最完整的一条记录（基于 PortInfo 的信息完整度评分）。
     * </p>
     *
     * @param ports 端口号字符串列表（例如 ["80", "443"]）。可以包含无效或重复的端口号，
     *              无效端口号（非数字、负数或大于 65535）将被忽略。
     * @return 返回一个 PortInfo 列表，包含指定端口中被占用的端口信息。
     *         如果输入为空、无效或没有端口被占用，返回空列表。
     *         <p>PortInfo 对象各属性的可能取值如下：</p>
     *         <ul>
     *           <li><b>portNumber</b>: 整数，输入端口列表中的有效端口号（0-65535），例如 80、443、6379。</li>
     *           <li><b>processName</b>: 字符串，进程名称（例如 "java"、"nginx"），可能为 ""（空字符串）或 null（取决于 oshi 实现）。</li>
     *           <li><b>processId</b>: 整数，通常为正数（例如 1234），表示进程 ID；可能为 0（无关联进程，但通常不会创建 PortInfo）。</li>
     *           <li><b>commandLine</b>: 字符串，进程的命令行（例如 "/usr/bin/java -jar app.jar"），可能为 "" 或 null（取决于 oshi 实现）。</li>
     *           <li><b>listenAddress</b>: 字符串，格式化的 IP 地址（例如 IPv4: "192.168.1.1"，IPv6: "2001:0db8:85a3:0000:0000:8a2e:0370:7334"），或 "unknown"（地址不可用），或十六进制字符串（未知格式，例如 "0a000001"）。</li>
     *         </ul>
     */
    public static List<PortInfo> getPortsUsage(List<String> ports) {
        if (ports == null || ports.isEmpty()) {
            return new ArrayList<>();
        }

        // Convert string ports to integers and validate
        Set<Integer> portSet = ports.stream()
                .filter(p -> p != null && p.matches("\\d+"))
                .map(Integer::parseInt)
                .filter(p -> p >= 0 && p <= 65535)
                .collect(Collectors.toSet());

        if (portSet.isEmpty()) {
            return new ArrayList<>();
        }

        // Find min and max ports for range query
        int minPort = portSet.stream().min(Integer::compare).orElse(0);
        int maxPort = portSet.stream().max(Integer::compare).orElse(65535);

        // Get all ports in range
        List<PortInfo> allPorts = getPortsUsage(minPort, maxPort);

        // Filter to only requested ports
        return allPorts.stream()
                .filter(info -> portSet.contains(info.getPortNumber()))
                .collect(Collectors.toList());
    }

    /**
     * 格式化IP地址字节数组为字符串
     *
     * @param addressBytes IP地址的字节数组
     * @return 格式化后的IP地址字符串
     */
    private static String formatAddress(byte[] addressBytes) {
        if (addressBytes == null || addressBytes.length == 0) {
            return "unknown";
        }

        // IPv4地址 (4字节)
        if (addressBytes.length == 4) {
            return String.format("%d.%d.%d.%d",
                    addressBytes[0] & 0xFF,
                    addressBytes[1] & 0xFF,
                    addressBytes[2] & 0xFF,
                    addressBytes[3] & 0xFF);
        }
        // IPv6地址 (16字节)
        else if (addressBytes.length == 16) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < addressBytes.length; i += 2) {
                if (i > 0) {
                    sb.append(':');
                }
                sb.append(String.format("%02x%02x", addressBytes[i] & 0xFF, addressBytes[i + 1] & 0xFF));
            }
            return sb.toString();
        } else {
            // 其他格式，返回字节数组的十六进制表示
            StringBuilder sb = new StringBuilder();
            for (byte b : addressBytes) {
                sb.append(String.format("%02x", b & 0xFF));
            }
            return sb.toString();
        }
    }

    /**
     * 获取单个端口的使用情况
     *
     * @param port 端口号
     * @return 端口信息列表
     */
    public static List<PortInfo> getPortUsage(int port) {
        return getPortsUsage(port, port);
    }

    /**
     * 判断指定端口是否被占用
     *
     * @param port 端口号
     * @return 是否被占用
     */
    public static boolean isPortInUse(int port) {
        return !getPortUsage(port).isEmpty();
    }


}