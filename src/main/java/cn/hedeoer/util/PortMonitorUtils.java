package cn.hedeoer.util;

import cn.hedeoer.pojo.PortInfo;
import oshi.SystemInfo;
import oshi.software.os.InternetProtocolStats;
import oshi.software.os.InternetProtocolStats.IPConnection;
import oshi.software.os.OSProcess;
import oshi.software.os.OperatingSystem;

import java.util.*;
import java.util.stream.Collectors;

/**
 * 端口监控工具类
 * 基于oshi-core库查询指定端口范围的使用情况
 */
public class PortMonitorUtils {


    /**
     * 获取指定端口范围内的所有被监听的端口使用情况。
     * <p>
     * 此方法通过 OSHI 库查询指定端口范围内的 TCP (LISTEN state) 和 UDP 连接，
     * 收集每个端口的占用情况，包括协议、端口号、关联进程的名称、进程 ID、
     * 命令行、监听的 IP 地址以及地址族 (IPv4/IPv6)。
     * 对于每个 (protocol, portNumber, family) 组合，仅保留信息最完整的一条记录。
     * </p>
     *
     * @param startPortStr 起始端口号（字符串，包含）。
     * @param endPortStr 结束端口号（字符串，包含）。
     * @return 返回一个 PortInfo 列表，包含范围内所有被占用的监听端口信息。
     *         列表中每个 (protocol, portNumber, family) 组合是唯一的。
     *         如果没有端口被监听或范围无效，返回空列表。
     *         <p>PortInfo 对象各属性的可能取值如下：</p>
     *         <ul>
     *           <li><b>protocol</b>: 字符串，固定为 "tcp" 或 "udp"。</li>
     *           <li><b>portNumber</b>: 整数，范围在 [startPort, endPort] 内。</li>
     *           <li><b>processName</b>: 字符串，进程名称（例如 "java", "sshd"）。如果进程信息不可用（如权限不足、进程已退出），则可能为 "Unknown"；对于某些系统级任务，可能为 "System"；如果OSHI未提供，则为空字符串 ""。</li>
     *           <li><b>processId</b>: 整数，进程 ID。通常为正数。如果 OSHI 无法确定所属进程（例如权限不足），则为 -1。对于某些系统级监听，PID 可能为 0。</li>
     *           <li><b>commandLine</b>: 字符串，进程的完整命令行。如果进程信息不可用或无相关命令行（例如 "System" 或 "Unknown" 状态的进程），则为空字符串 ""。</li>
     *           <li><b>listenAddress</b>: 字符串，监听的 IP 地址。例如 IPv4 的 "0.0.0.0"（监听所有 IPv4）、"127.0.0.1"，或 IPv6 的 "::"（监听所有 IPv6）、"fe80::1"。如果地址信息无效或无法解析，则可能为 "unknown" 或 "invalid_address_bytes"。</li>
     *           <li><b>family</b>: 字符串，表示地址族，值为 ipv4 或 ipv6。</li>
     *         </ul>
     * @throws IllegalArgumentException 如果 startPort 大于 endPort 或端口范围无效。
     */
    public static List<PortInfo> getPortsUsage(String startPortStr, String endPortStr) {

        if ((startPortStr == null || startPortStr.isEmpty()) || (endPortStr == null || endPortStr.isEmpty())) {
            return Collections.emptyList();
        }

        // 仅允许数字
        if (!startPortStr.matches("\\d+") || !endPortStr.matches("\\d+")) {
            System.err.println("端口号必须是正整数。");
            return Collections.emptyList();
        }

        int startPort = Integer.parseInt(startPortStr);
        int endPort = Integer.parseInt(endPortStr);

        if (startPort > endPort || startPort < 0 || endPort > 65535) {
            throw new IllegalArgumentException("端口范围无效：起始端口必须小于或等于结束端口，且范围在 [0, 65535]");
        }

        SystemInfo systemInfo = new SystemInfo();
        OperatingSystem os = systemInfo.getOperatingSystem();
        InternetProtocolStats ipStats = os.getInternetProtocolStats();

        // Map to store the best PortInfo for each (protocol, port, family) combination
        Map<String, PortInfo> portInfoMap = new HashMap<>();
        List<IPConnection> allConnections = ipStats.getConnections();

        for (IPConnection conn : allConnections) {
            int localPort = conn.getLocalPort();

            if (localPort >= startPort && localPort <= endPort) {
                String oshiType = conn.getType(); // "tcp4", "tcp6", "udp4", "udp6"
                String determinedProtocol;
                String determinedFamily;

                // Determine protocol and family
                if ("tcp4".equals(oshiType)) {
                    determinedProtocol = "tcp";
                    determinedFamily = "ipv4";
                } else if ("tcp6".equals(oshiType)) {
                    determinedProtocol = "tcp";
                    determinedFamily = "ipv6";
                } else if ("udp4".equals(oshiType)) {
                    determinedProtocol = "udp";
                    determinedFamily = "ipv4";
                } else if ("udp6".equals(oshiType)) {
                    determinedProtocol = "udp";
                    determinedFamily = "ipv6";
                } else {
                    // Should not happen with current LinuxInternetProtocolStats implementation
                    // System.err.println("未知 OSHI 连接类型: " + oshiType);
                    continue;
                }

                // --- Filter for listening ports ---
                boolean isListening = false;
                if ("tcp".equals(determinedProtocol)) {
                    // For TCP, only consider ports in LISTEN state
                    if (conn.getState() == InternetProtocolStats.TcpState.LISTEN) {
                        isListening = true;
                    }
                } else { // For UDP
                    // UDP is connectionless. Sockets in /proc/net/udp are bound and can receive.
                    // We consider all UDP entries in the port range as "listening".
                    // A more stringent check might involve foreign address being 0.0.0.0/:: and foreign port 0,
                    // but OSHI already provides these as distinct entries.
                    isListening = true;
                }

                if (!isListening) {
                    continue; // Skip non-listening TCP connections or other undesired states
                }
                // --- End filter ---


                // Create composite key for (protocol, portNumber, family)
                String key = determinedProtocol + ":" + localPort + ":" + determinedFamily;

                int pid = conn.getowningProcessId(); // Javadoc says -1 if unknown, Linux impl uses -1 as default
                String listenAddressStr = formatAddress(conn.getLocalAddress());
                OSProcess process = pid > 0 ? os.getProcess(pid) : null; // Only query if PID is positive

                String processName = "";
                String commandLine = "";

                if (process != null) {
                    processName = process.getName();
                    commandLine = process.getCommandLine();
                } else if (pid <= 0) { // PID is 0, -1 or some other non-positive: system process or unknown
                    processName = (pid == 0) ? "System" : "Unknown";
                    // commandLine remains ""
                }


                PortInfo newInfo = PortInfo.builder()
                        .protocol(determinedProtocol)
                        .portNumber(localPort)
                        .processName(processName != null ? processName : "")
                        .processId(pid) // Store the original PID, even if <= 0
                        .commandLine(commandLine != null ? simplifyCommandLine(commandLine) : "")
                        .listenAddress(listenAddressStr)
                        .family(determinedFamily)
                        .build();

                // Update if no existing info or new info is more complete
                // Ensure PortInfo has gainInfoCompletenessScore() implemented
                portInfoMap.compute(key, (k, existingInfo) -> {
                    // 1. 如果 map 中还没有这个 key (即没有关于这个端口的记录)
                    if (existingInfo == null) {
                        // 那么直接使用新获取到的 PortInfo 对象 (newInfo) 作为这个 key 的值
                        return newInfo;
                    }

                    // 2. 如果 map 中已经存在这个 key (即之前已经记录过这个端口的信息)
                    //    这通常不应该发生，因为我们对 LISTEN 状态的端口，(protocol, port, family) 应该是唯一的。
                    //    但如果因为某些特殊情况（例如，OSHI返回了重复的监听条目，或者我们的key不够唯一）
                    //    或者如果这个逻辑被用于非LISTEN状态的连接（但我们之前的过滤应该是处理了这一点），
                    //    我们就需要决定是保留旧的 (existingInfo) 还是用新的 (newInfo) 替换它。
                    //    这里的策略是：比较哪个 PortInfo 对象的信息更“完整”。

                    //    调用 PortInfo 对象上的一个方法 gainInfoCompletenessScore() 来获取一个“信息完整度评分”。
                    //    这个评分越高，代表信息越完整（例如，有PID、有进程名、有命令行等）。
                    if (newInfo.gainInfoCompletenessScore() > existingInfo.gainInfoCompletenessScore()) {
                        // 如果新获取的 PortInfo (newInfo) 比已存在的 (existingInfo) 更完整，
                        // 就返回 newInfo，这样 map 中 key 对应的值就会被更新为 newInfo。
                        return newInfo;
                    } else {
                        // 否则 (如果 existingInfo 更完整或两者一样完整)，
                        // 就返回 existingInfo，保持 map 中原有的记录不变。
                        return existingInfo;
                    }
                });
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
     * 每个 (protocol, portNumber) 组合仅保留信息最完整的一条记录（基于 PortInfo 的信息完整度评分）。
     * </p>
     *
     * @param ports 端口号字符串列表（例如 ["80", "443"]）。可以包含无效或重复的端口号，
     *              无效端口号（非数字、负数或大于 65535）将被忽略。
     * @return 返回一个 PortInfo 列表，包含指定端口中被占用的端口信息。
     *         列表中每个 (protocol, portNumber) 组合是唯一的。
     *         如果输入为空、无效或没有端口被占用，返回空列表。
     *         <p>PortInfo 对象各属性的可能取值如下：</p>
     *         <ul>
     *           <li><b>protocol</b>: 字符串，"tcp" 或 "udp"。</li>
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


        // Get all ports in range (includes protocol information)
        List<PortInfo> allPorts = getPortsUsage(minPort + "", maxPort + "");

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
    public static List<PortInfo> getPortUsage(String port) {
        return getPortsUsage(port, port);
    }

    /**
     * 判断指定端口是否被占用
     *
     * @param port 端口号
     * @return 是否被占用
     */
    public static boolean isPortInUse(String port) {
        return !getPortUsage(port).isEmpty();
    }


    /**
     * 各个协议对应的多个端口是否有被使用的？
     *
     * @param port 一些端口或者单个端口
     * @param protocol 协议 （tcp, udp, tcp/udp 正常情况有三种取值情况）
     * @return 所有端口都未被使用，为空列表；端口中有端口被使用，正在被使用端口
     */
    public static List<PortInfo> getPortsInUse(String port, String protocol) {

        // 存储最终的查询结果
        ArrayList<PortInfo> result = new ArrayList<>();

        // 存储被使用的端口信息(不区分协议)，为空表示没有端口被使用
        List<PortInfo> portInfos = new ArrayList<>();

        // 处理异常情况
        if (port == null || port.isEmpty() || protocol == null || protocol.isEmpty()) {
             return portInfos;
        }



        // 多个端口的情况
        if (port.contains(",")) {
            List<String> ports = List.of(port.split(","));
            // ports中所有正在使用的情况，区分协议类型
            portInfos = getPortsUsage(ports);
        }else if (port.contains("-")) {
            String[] startAndEnd = port.split("-");
            // ports中所有正在使用的情况，区分协议类型
            portInfos = getPortsUsage(startAndEnd[0], startAndEnd[1]);
        }else{
            // ports中所有正在使用的情况，区分协议类型
            portInfos = getPortUsage(port);
        }

        //处理多个协议 和 单个协议 的情况
        String[] protocolTypes = protocol.split("/");
        for (String protocolType : protocolTypes) {
            for (PortInfo portInfo : portInfos) {
                if (portInfo.getProtocol().equalsIgnoreCase(protocolType)) {
                    result.add(portInfo);
                }
            }
        }

        return portInfos;
    }

    /**
     * 获取机器上 22-65535 范围内当前被使用的端口号列表
     *
     * @return 返回被使用的端口号列表，如果没有端口被使用则返回空列表
     */
    public static List<PortInfo> getUsedPortsAbove22() {
        // 使用现有的 getPortsUsage 方法获取端口信息
        return getPortsUsage("22", "65535");
    }


    /**
     * 原始命令行	简化后
     * /usr/bin/python3 -m http.server 8080	python3 http.server
     * /usr/bin/node server.js	node server.js
     * /usr/bin/nginx -c /etc/nginx/nginx.conf	nginx
     * /usr/bin/redis-server /etc/redis.conf --daemonize yes	redis-server redis.conf
     * /usr/bin/sh /tmp/start.sh	sh start.sh
     * /usr/bin/perl script.pl -d	perl script.pl
     * /usr/bin/git daemon --reuseaddr --base-path=/srv/git /srv/git	git daemon
     * /usr/local/bin/mysqld_safe --datadir=/var/lib/mysql	mysqld_safe
     * @param commandLine 原始命令
     * @return 简短字符命令
     */
    private static String simplifyCommandLine(String commandLine) {
        if (commandLine == null || commandLine.isEmpty()) return "";

        String[] parts = commandLine.trim().split("\\s+");
        if (parts.length == 0) return "";

        // 主程序名
        String program = parts[0].substring(parts[0].lastIndexOf('/') + 1);

        // Java特判可放前面（用之前的java逻辑），下方是通用部分
        if ("java".equals(program)) {
            // 1. 提取 -jar 后面的 jar 名
            for (int i = 1; i < parts.length - 1; i++) {
                if ("-jar".equals(parts[i])) {
                    String jar = parts[i + 1];
                    jar = jar.substring(jar.lastIndexOf('/') + 1);
                    return "java " + jar;
                }
            }
            // 2. 从最后向前找最长右侧的主类（非-参数，且带.，且结尾有.Main可能更精确）
            for (int i = parts.length - 1; i >= 1; i--) {
                if (!parts[i].startsWith("-") && !parts[i].startsWith("/")) {
                    String mainClass = parts[i];
                    int lastDot = mainClass.lastIndexOf('.');
                    // 限制只显示最简单的 Main，如果没有点，则直接输出
                    return "java " + (lastDot > 0 ? mainClass.substring(lastDot + 1) : mainClass);
                }
            }
            // 兜底
            return "java";
        }

        // 通用处理
        StringBuilder result = new StringBuilder(program);
        boolean skipNext = false;
        int nonOptionCount = 0;

        for (int i = 1; i < parts.length && nonOptionCount < 2; i++) {
            String p = parts[i];
            // 1. 跳过参数
            if (p.startsWith("-")) {
                // 如果是 -m、-module、run 等，保留后面一个
                if (p.equals("-m") || p.equals("run")) {
                    skipNext = true;
                }
                continue;
            }
            // 2. 上一个参数要求保留本词
            if (skipNext) {
                result.append(" ").append(p);
                nonOptionCount++;
                skipNext = false;
                continue;
            }
            // 3. 普通可疑是主文件/主脚本/主js/主py等
            if (p.startsWith("/")) {
                // 只保留文件名，去掉路径
                p = p.substring(p.lastIndexOf('/') + 1);
            }
            result.append(" ").append(p);
            nonOptionCount++;
        }
        return result.toString().trim();
    }
}