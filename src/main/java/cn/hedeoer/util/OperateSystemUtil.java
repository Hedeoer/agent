package cn.hedeoer.util;

import cn.hedeoer.common.enmu.OSType;
import oshi.SystemInfo;
import oshi.hardware.CentralProcessor;
import oshi.hardware.GlobalMemory;
import oshi.software.os.FileSystem;
import oshi.software.os.OSFileStore;

import java.io.*;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

public class OperateSystemUtil {
    private static final SystemInfo systemInfo = new SystemInfo();
    /*
    * 用于判断宿主机的操作系统类型
    *
    * */
    public static final String OS_NAME = "os.name";

    public static OSType getOSType(Properties systemProperties){
        if(systemProperties == null){
            systemProperties = System.getProperties();
        }
        String osName = systemProperties.getProperty(OS_NAME);
        if(osName == null){
            return OSType.UNKNOWN;
        }
        osName = osName.toLowerCase();
        if(osName.contains("windows")){//eg: "Windows 10"
            return OSType.WINDOWS;
        } else if(osName.contains("linux")){//"nux" | eg : "Linux"
            return OSType.LINUX;
        } else if(osName.contains("unix")) {//"nix"
            return OSType.UNIX;
        } else if(osName.contains("mac")){//eg: "Mac OS X"
            return OSType.MAC;
        } else if(osName.contains("sol")){//"sol"
            return OSType.SOLARIS;
        }
        return OSType.UNKNOWN;
    }

    /**
     * 获取操作系统架构
     * @return 操作系统架构（x86, amd64, arm等）
     */
    public static String getOSArch() {
        return System.getProperty("os.arch");
    }

    /**
     * 获取操作系统版本
     * @return 操作系统版本
     */
    public static String getOSVersion() {
        return System.getProperty("os.version");
    }

    /**
     * 判断当前操作系统是否是Windows
     * @return 是否是Windows系统
     */
    public static boolean isWindows() {
        return getOSType(null).equals(OSType.WINDOWS);
    }

    /**
     * 判断当前操作系统是否是Linux
     * @return 是否是Linux系统
     */
    public static boolean isLinux() {
        return getOSType(null).equals(OSType.LINUX);
    }

    /**
     * 判断宿主机是否具有JRE
     * @return 是否具有JRE
     */
    public static boolean ownJavaEnvironment() {
        return getJVMVersion().isEmpty();
    }

    /**
     * 获取Linux发行版信息
     * @return 包含Linux发行版信息的Map
     */
    public static Map<String, String> getLinuxDistribution() {
        Map<String, String> distInfo = new HashMap<>();

        if (!isLinux()) {
            distInfo.put("error", "Not a Linux system");
            return distInfo;
        }

        // 尝试从/etc/os-release文件获取信息
        try {
            File osReleaseFile = new File("/etc/os-release");
            if (osReleaseFile.exists()) {
                try (BufferedReader reader = new BufferedReader(new FileReader(osReleaseFile))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (line.contains("=")) {
                            String[] parts = line.split("=", 2);
                            if (parts.length == 2) {
                                String key = parts[0];
                                String value = parts[1].replace("\"", "");
                                distInfo.put(key, value);
                            }
                        }
                    }
                    return distInfo;
                }
            }

            // 尝试其他发行版特定文件
            File[] distFiles = {
                    new File("/etc/redhat-release"),  // RHEL, CentOS
                    new File("/etc/debian_version"),  // Debian
                    new File("/etc/lsb-release")      // Ubuntu
            };

            for (File file : distFiles) {
                if (file.exists()) {
                    try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                        String content = reader.readLine();
                        if (content != null) {
                            distInfo.put("DISTRIB_DESCRIPTION", content);
                            return distInfo;
                        }
                    }
                }
            }

            // 尝试使用命令行工具
            String[] commands = {"lsb_release -a", "cat /etc/*-release"};
            for (String cmd : commands) {
                try {
                    Process process = Runtime.getRuntime().exec(cmd);
                    try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            distInfo.put("cmd_output", (distInfo.getOrDefault("cmd_output", "") + line + "\n"));
                        }
                    }
                    if (!distInfo.isEmpty()) {
                        return distInfo;
                    }
                } catch (IOException e) {
                    // 忽略命令执行错误，尝试下一个命令
                }
            }
        } catch (Exception e) {
            distInfo.put("error", e.getMessage());
        }

        return distInfo;
    }

    /**
     * 获取Windows版本详细信息
     * @return Windows版本详细信息
     */
    public static String getWindowsVersionDetails() {
        if (!isWindows()) {
            return "Not a Windows system";
        }

        try {
            Process process = Runtime.getRuntime().exec("systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\"");
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
                return output.toString();
            }
        } catch (IOException e) {
            return "Error getting Windows version: " + e.getMessage();
        }
    }

    /**
     * 获取Java版本
     * @return Java版本
     */
    public static String getJavaVersion() {
        return System.getProperty("java.version");
    }

    /**
     * 获取Java供应商
     * @return Java供应商
     */
    public static String getJavaVendor() {
        return System.getProperty("java.vendor");
    }

    /**
     * 获取Java虚拟机名称
     * @return JVM名称
     */
    public static String getJVMName() {
        return System.getProperty("java.vm.name");
    }

    /**
     * 获取Java虚拟机版本
     * @return JVM版本
     */
    public static String getJVMVersion() {
        return System.getProperty("java.vm.version");
    }

    /**
     * 获取Java虚拟机供应商
     * @return JVM供应商
     */
    public static String getJVMVendor() {
        return System.getProperty("java.vm.vendor");
    }

    /**
     * 获取完整的系统和Java信息
     * @return 包含所有信息的Map
     */
    public static Map<String, String> getAllSystemInfo() {
        Map<String, String> info = new HashMap<>();

        // 操作系统信息
        info.put("os.name", getOSType(null).getName());
        info.put("os.version", getOSVersion());
        info.put("os.arch", getOSArch());

        // 特定操作系统信息
        if (isWindows()) {
            info.put("windows.details", getWindowsVersionDetails());
        } else if (isLinux()) {
            Map<String, String> distInfo = getLinuxDistribution();
            for (Map.Entry<String, String> entry : distInfo.entrySet()) {
                info.put("linux." + entry.getKey(), entry.getValue());
            }
        }


        // Java信息
        info.put("java.version", getJavaVersion());
        info.put("java.vendor", getJavaVendor());
        info.put("java.vm.name", getJVMName());
        info.put("java.vm.version", getJVMVersion());
        info.put("java.vm.vendor", getJVMVendor());

        return info;
    }

    /**
     * 获取主机名，兼容多操作系统
     */
    public static String getHostName() {
        try {
            // 通用方法优先（几乎所有平台有效）
            String hostname = InetAddress.getLocalHost().getHostName();
            if (hostname != null && !hostname.isBlank() && !hostname.equals("localhost")) {
                return hostname;
            }
        } catch (Exception ignored) {
        }
        // 如果上面失败，再根据操作系统类型特殊处理
        OSType osType = getOSType(null);
        String hostname = null;
        switch (osType) {
            case WINDOWS:
                hostname = System.getenv("COMPUTERNAME");
                break;
            case LINUX:
            case UNIX:
            case SOLARIS:
            case MAC:
                hostname = System.getenv("HOSTNAME");
                break;
            default:
                // 用尽所有办法都没有，那就unknown
                hostname = "unknown-host";
        }
        // 防御性，如果还没有
        if (hostname == null || hostname.isBlank()) {
            hostname = "unknown-host";
        }
        return hostname;
    }

    // 获取CPU总使用率（需要等待一次采样，否则恒0.0）
    public static String getCpuUsage() {
        double cpuLoad = 0;
        try {
            CentralProcessor processor = systemInfo.getHardware().getProcessor();
            long[] prevTicks = processor.getSystemCpuLoadTicks();
            Thread.sleep(1000); // 等待1秒采样
            long[] ticks = processor.getSystemCpuLoadTicks();
            cpuLoad = processor.getSystemCpuLoadBetweenTicks(prevTicks);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        return String.format("%.2f",cpuLoad * 100);
    }
    // 获取物理内存使用率
    public static String getMemoryUsage() {
        GlobalMemory memory = systemInfo.getHardware().getMemory();
        long total = memory.getTotal();
        long available = memory.getAvailable();
        long used = total - available;
        if (total == 0) return "0.0";
        return String.format("%.2f",used * 100.0 / total);
    }
    // 获取所有分区磁盘使用率平均值（如需主分区可只取第一个）
    public static String getAvgDiskUsage() {
        FileSystem fileSystem = systemInfo.getOperatingSystem().getFileSystem();
        List<OSFileStore> fileStores = fileSystem.getFileStores();
        double total = 0.0;
        double used = 0.0;
        for (OSFileStore fs : fileStores) {
            long t = fs.getTotalSpace();
            long u = t - fs.getUsableSpace();
            if (t <= 0) continue;
            total += t;
            used += u;
        }
        if (total == 0) return "0.0";
        return String.format("%.2f",used * 100.0 / total);
    }
}
