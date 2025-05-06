package cn.hedeoer.util;

import java.net.*;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class IpUtils {

    /**
     * 判断给定的IP地址是否为IPv4地址
     *
     * @param ip IP地址字符串
     * @return 如果是IPv4地址则返回true，否则返回false
     */
    public static boolean isIpv4(String ip) {
        try {
            InetAddress inetAddress = InetAddress.getByName(ip);
            return inetAddress instanceof Inet4Address;
        } catch (UnknownHostException e) {
            return false;
        }
    }

    /**
     * 判断给定的IP地址是否为IPv6地址（支持CIDR表示法）
     *
     * @param ipWithPossibleCidr IP地址字符串，可能包含CIDR表示法
     * @return 如果是IPv6地址则返回true，否则返回false
     */
    public static boolean isIpv6(String ipWithPossibleCidr) {
        // 移除CIDR部分（如果存在）
        String ip = ipWithPossibleCidr;
        if (ip.contains("/")) {
            ip = ip.substring(0, ip.indexOf("/"));
        }

        try {
            InetAddress inetAddress = InetAddress.getByName(ip);
            return inetAddress instanceof Inet6Address;
        } catch (UnknownHostException e) {
            return false;
        }
    }

    /**
     * 获取IP地址类型
     *
     * @param ip IP地址字符串
     * @return 返回"ipv4"、"ipv6"或"Unknown"
     */
    public static String getIpType(String ip) {
        // 增加ip区间的判断
        if (ip.contains("-")) {
            ip = ip.split("-")[0];
        }
        if (ip.contains(",")) {
            ip = ip.split(",")[0];
        }

        if (isIpv4(ip)) {
            return "ipv4";
        } else if (isIpv6(ip)) {
            return "ipv6";
        } else {
            return "Unknown";
        }
    }

    /**
     * 判断给定的IP字符串是否为有效的IP地址（IPv4或IPv6）
     *
     * @param ip IP地址字符串
     * @return 如果是有效的IP地址则返回true，否则返回false
     */
    public static boolean isValidIp(String ip) {
        return isIpv4(ip) || isIpv6(ip);
    }
    
    /**
     * 判断给定的字符串是否为有效的CIDR表示法（包括IPv4和IPv6）
     *
     * @param cidr CIDR表示法字符串 (如 "192.168.1.0/24" 或 "2001:db8::/32")
     * @return 如果是有效的CIDR则返回true，否则返回false
     */
    public static boolean isValidCidr(String cidr) {
        if (cidr == null || cidr.isEmpty()) {
            return false;
        }
        
        String[] parts = cidr.split("/");
        if (parts.length != 2) {
            return false;
        }
        
        String ip = parts[0];
        String prefixLengthStr = parts[1];
        
        try {
            int prefixLength = Integer.parseInt(prefixLengthStr);
            
            if (isIpv4(ip)) {
                // IPv4 的前缀长度范围是 0-32
                return prefixLength >= 0 && prefixLength <= 32;
            } else if (isIpv6(ip)) {
                // IPv6 的前缀长度范围是 0-128
                return prefixLength >= 0 && prefixLength <= 128;
            } else {
                return false;
            }
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * IP地址信息类
     */
    public static class IpInfo {
        private String address;     // IP地址或CIDR表示的IP段
        private boolean isIpv4;     // 是否为IPv4
        private boolean isIpv6;     // 是否为IPv6
        private boolean isCidr;     // 是否为CIDR格式(IP段)
        public IpInfo(String address, boolean isIpv4, boolean isIpv6, boolean isCidr) {
            this.address = address;
            this.isIpv4 = isIpv4;
            this.isIpv6 = isIpv6;
            this.isCidr = isCidr;
        }
        public String getAddress() {
            return address;
        }
        public boolean isIpv4() {
            return isIpv4;
        }
        public boolean isIpv6() {
            return isIpv6;
        }
        public boolean isCidr() {
            return isCidr;
        }
        /**
         * 获取firewalld富规则使用的family参数
         */
        public String getFirewalldFamily() {
            return isIpv4 ? "ipv4" : "ipv6";
        }
        @Override
        public String toString() {
            String type = isIpv4 ? "IPv4" : "IPv6";
            String format = isCidr ? "CIDR网段" : "单个地址";
            return address + " (" + type + ", " + format + ")";
        }
    }
    /**
     * 解析包含一个或多个IP地址/网段的输入字符串
     *
     * @param input 输入字符串，例如 "172.16.10.11" 或 "172.16.0.0/24" 或 "172.16.10.11,172.16.0.0/24"
     * @return 解析后的IP信息列表
     * @throws IllegalArgumentException 如果输入包含无效的IP地址
     */
    public static List<IpInfo> parseIpAddresses(String input) {
        if (input == null || input.trim().isEmpty()) {
            throw new IllegalArgumentException("IP地址不能为空");
        }
        List<IpInfo> result = new ArrayList<>();
        String[] items = input.split(",");
        for (String item : items) {
            String trimmedItem = item.trim();
            if (trimmedItem.isEmpty()) {
                continue;
            }
            IpInfo ipInfo = parseIpAddress(trimmedItem);
            if (ipInfo != null) {
                result.add(ipInfo);
            } else {
                throw new IllegalArgumentException("无效的IP地址或网段: " + trimmedItem);
            }
        }
        if (result.isEmpty()) {
            throw new IllegalArgumentException("未找到有效的IP地址");
        }

        return result;
    }
    /**
     * 解析单个IP地址或CIDR
     *
     * @param ip IP地址字符串
     * @return IP信息对象，如果无效则返回null
     */
    private static IpInfo parseIpAddress(String ip) {
        boolean isCidr = ip.contains("/");

        if (isCidr) {
            return parseCidrAddress(ip);
        } else {
            try {
                InetAddress inetAddress = InetAddress.getByName(ip);
                boolean isIpv4 = inetAddress instanceof Inet4Address;
                boolean isIpv6 = inetAddress instanceof Inet6Address;

                if (isIpv4 || isIpv6) {
                    return new IpInfo(ip, isIpv4, isIpv6, false);
                }
            } catch (UnknownHostException e) {
                return null;
            }
        }

        return null;
    }
    /**
     * 解析CIDR格式的地址
     *
     * @param cidr CIDR表示法字符串
     * @return IP信息对象，如果无效则返回null
     */
    private static IpInfo parseCidrAddress(String cidr) {
        String[] parts = cidr.split("/");
        if (parts.length != 2) {
            return null;
        }

        String ip = parts[0];
        String prefixLengthStr = parts[1];

        try {
            int prefixLength = Integer.parseInt(prefixLengthStr);
            InetAddress inetAddress = InetAddress.getByName(ip);

            boolean isIpv4 = inetAddress instanceof Inet4Address;
            boolean isIpv6 = inetAddress instanceof Inet6Address;

            // 验证前缀长度
            if (isIpv4 && (prefixLength < 0 || prefixLength > 32)) {
                return null;
            } else if (isIpv6 && (prefixLength < 0 || prefixLength > 128)) {
                return null;
            }

            if (isIpv4 || isIpv6) {
                return new IpInfo(cidr, isIpv4, isIpv6, true);
            }
        } catch (NumberFormatException | UnknownHostException e) {
            return null;
        }

        return null;
    }

    // 获取本机主IP（剔除127/本地回环等，仅获取常用公网或内网地址）
    public static String getLocalIpAddress() {
        try {
            // 优先遍历所有网卡，适配复杂多网卡主机
            Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
            while (ifaces.hasMoreElements()) {
                NetworkInterface iface = ifaces.nextElement();
                // 跳过down、虚拟、环回
                if (!iface.isUp() || iface.isLoopback() || iface.isVirtual()) continue;
                Enumeration<InetAddress> addrs = iface.getInetAddresses();
                while (addrs.hasMoreElements()) {
                    InetAddress addr = addrs.nextElement();
                    // 只要IPv4，且不是回环、链路本地和多播
                    if (addr instanceof Inet4Address
                            && !addr.isLoopbackAddress()
                            && !addr.isLinkLocalAddress()
                            && !addr.isMulticastAddress()) {
                        return addr.getHostAddress();
                    }
                }
            }
            // 没有则兜底
            return InetAddress.getLocalHost().getHostAddress();
        } catch (Exception e) {
            return "unknown-ip";
        }
    }

    public static void main(String[] args) {
        // 解析IP地址
        String input = "172.16.10.11,172.16.0.0/24,2001:db8::1";
        List<IpInfo> ipInfos = IpUtils.parseIpAddresses(input);
        ipInfos.forEach(System.out::println);
    }
}
