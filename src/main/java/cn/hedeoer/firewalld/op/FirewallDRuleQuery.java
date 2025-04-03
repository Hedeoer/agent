package cn.hedeoer.firewalld.op;

import org.freedesktop.dbus.annotations.DBusInterfaceName;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.connections.impl.DBusConnectionBuilder;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.interfaces.DBusInterface;
import org.freedesktop.dbus.interfaces.Properties;
import org.freedesktop.dbus.types.Variant;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * FirewallD规则查询工具类
 */
public class FirewallDRuleQuery {
    // DBus连接地址常量
    private static final String FIREWALLD_BUS_NAME = "org.fedoraproject.FirewallD1";
    private static final String FIREWALLD_PATH = "/org/fedoraproject/FirewallD1";
    private static final String FIREWALLD_ZONE_INTERFACE = "org.fedoraproject.FirewallD1.zone";
    private static final String FIREWALLD_DIRECT_INTERFACE = "org.fedoraproject.FirewallD1.direct";
    private static final String FIREWALLD_MAIN_INTERFACE = "org.fedoraproject.FirewallD1";
    private static final String FIREWALLD_IPSET_INTERFACE = "org.fedoraproject.FirewallD1.ipset";
    private static final String PROPERTIES_INTERFACE = "org.freedesktop.DBus.Properties";

    private DBusConnection connection;


    public FirewallDRuleQuery() {

        // 获取FirewallD连接
        try {

            // 授权 firewalld操作
            if (FirewallPolicyConfigurer.configureFirewallPolicy()) {
                // 获取firewalld链接
                connection = DBusConnectionBuilder.forSystemBus().build();
            }
        } catch (DBusException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 获取  DBusConnection
     * @return  connection ；null标识获取失败
     */
    public static DBusConnection getDBusConnection(){
        DBusConnection connection = null;
        // 获取FirewallD连接
        try {

            // 授权 firewalld操作
            if (FirewallPolicyConfigurer.configureFirewallPolicy()) {
                // 获取firewalld链接
                connection = DBusConnectionBuilder.forSystemBus().build();
            }
            return connection;
        } catch (DBusException e) {
            throw new RuntimeException(e);
        }
    }



    /**
     * 关闭连接
     */
    public void disconnect() throws IOException {
        if (connection != null) {
            connection.close();
        }
    }


    /**
     * 获取FirewallD版本信息
     */
    public Map<String, Object> getFirewallDInfo() throws DBusException {
        Map<String, Object> info = new HashMap<>();
        
        Properties properties = connection.getRemoteObject(
                FIREWALLD_BUS_NAME,
                FIREWALLD_PATH,
                Properties.class);
        
        Map<String, Variant<?>> props = properties.GetAll(FIREWALLD_MAIN_INTERFACE);
        
        info.put("version", props.get("version"));
        info.put("state", props.get("state"));
        info.put("interface_version", props.get("interface_version"));
        info.put("IPv4", props.get("IPv4"));
        info.put("IPv6", props.get("IPv6"));
        
        return info;
    }

    /**
     * 获取默认区域
     */
    public String getDefaultZone() throws DBusException {
        FirewallDInterface firewalld = connection.getRemoteObject(
                FIREWALLD_BUS_NAME, 
                FIREWALLD_PATH, 
                FirewallDInterface.class);
        
        return firewalld.getDefaultZone();
    }

    /**
     * 获取所有区域列表
     */
    public List<String> getZones() throws DBusException {
        FirewallDZoneInterface zoneInterface = connection.getRemoteObject(
                FIREWALLD_BUS_NAME, 
                FIREWALLD_PATH, 
                FirewallDZoneInterface.class);
        
        return Arrays.asList(zoneInterface.getZones());
    }
    
    /**
     * 获取活动区域及其接口
     */
    public Map<String, Map<String, List<String>>> getActiveZones() throws DBusException {
        FirewallDZoneInterface zoneInterface = connection.getRemoteObject(
                FIREWALLD_BUS_NAME, 
                FIREWALLD_PATH, 
                FirewallDZoneInterface.class);
        
        return zoneInterface.getActiveZones();
    }

    /**
     * 获取区域详细配置
     */
    public Map<String, Object> getZoneConfig(String zoneName) throws DBusException {
        Map<String, Object> zoneConfig = new HashMap<>();
        
        FirewallDZoneInterface zoneInterface = connection.getRemoteObject(
                FIREWALLD_BUS_NAME, 
                FIREWALLD_PATH, 
                FirewallDZoneInterface.class);
        
        // 获取区域中的服务列表
        String[] services = zoneInterface.getServices(zoneName);
        zoneConfig.put("services", services);
        
        // 获取区域中的端口列表
        String[][] ports = zoneInterface.getPorts(zoneName);
        zoneConfig.put("ports", ports);
        
        // 获取区域中的源端口列表
        String[][] sourcePorts = zoneInterface.getSourcePorts(zoneName);
        zoneConfig.put("sourcePorts", sourcePorts);
        
        // 获取区域中的协议列表
        String[] protocols = zoneInterface.getProtocols(zoneName);
        zoneConfig.put("protocols", protocols);
        
        // 获取区域中的接口列表
        String[] interfaces = zoneInterface.getInterfaces(zoneName);
        zoneConfig.put("interfaces", interfaces);
        
        // 获取区域中的源地址列表
        String[] sources = zoneInterface.getSources(zoneName);
        zoneConfig.put("sources", sources);
        
        // 获取区域中的富规则列表
        String[] richRules = zoneInterface.getRichRules(zoneName);
        zoneConfig.put("richRules", richRules);
        
        // 获取区域中的转发端口列表
        String[][] forwardPorts = zoneInterface.getForwardPorts(zoneName);
        zoneConfig.put("forwardPorts", forwardPorts);
        
        // 检查区域中是否启用了伪装
        boolean masquerade = zoneInterface.queryMasquerade(zoneName);
        zoneConfig.put("masquerade", masquerade);
        
        // 获取ICMP阻止列表
        String[] icmpBlocks = zoneInterface.getIcmpBlocks(zoneName);
        zoneConfig.put("icmpBlocks", icmpBlocks);
        
        // 检查ICMP阻止反转
        boolean icmpBlockInversion = zoneInterface.queryIcmpBlockInversion(zoneName);
        zoneConfig.put("icmpBlockInversion", icmpBlockInversion);
        
        return zoneConfig;
    }

    /**
     * 获取直接规则
     */
    public Map<String, Object> getDirectRules() throws DBusException {
        Map<String, Object> directRules = new HashMap<>();
        
        FirewallDDirectInterface directInterface = connection.getRemoteObject(
                FIREWALLD_BUS_NAME, 
                FIREWALLD_PATH, 
                FirewallDDirectInterface.class);
        
        // 获取所有链
        Object[] allChains = directInterface.getAllChains();
        directRules.put("chains", allChains);
        
        // 获取所有规则
        Object[] allRules = directInterface.getAllRules();
        directRules.put("rules", allRules);
        
        // 获取所有直接通过规则
        Object[] allPassthroughs = directInterface.getAllPassthroughs();
        directRules.put("passthroughs", allPassthroughs);
        
        return directRules;
    }
    
    /**
     * 获取IPSet列表及其设置
     */
    public Map<String, Object> getIPSets() throws DBusException {
        Map<String, Object> ipsetInfo = new HashMap<>();
        
        FirewallDIPSetInterface ipsetInterface = connection.getRemoteObject(
                FIREWALLD_BUS_NAME, 
                FIREWALLD_PATH, 
                FirewallDIPSetInterface.class);
        
        // 获取所有IPSet名称
        String[] ipsets = ipsetInterface.getIPSets();
        
        // 获取各IPSet的详细配置
        Map<String, Object> ipsetDetails = new HashMap<>();
        for (String ipset : ipsets) {
            Object settings = ipsetInterface.getIPSetSettings(ipset);
            String[] entries = ipsetInterface.getEntries(ipset);
            
            Map<String, Object> ipsetData = new HashMap<>();
            ipsetData.put("settings", settings);
            ipsetData.put("entries", entries);
            
            ipsetDetails.put(ipset, ipsetData);
        }
        
        ipsetInfo.put("ipsets", ipsets);
        ipsetInfo.put("details", ipsetDetails);
        
        return ipsetInfo;
    }

    /**
     * 获取服务设置
     */
    public Object getServiceSettings(String serviceName) throws DBusException {
        FirewallDInterface firewalld = connection.getRemoteObject(
                FIREWALLD_BUS_NAME, 
                FIREWALLD_PATH, 
                FirewallDInterface.class);
        
        return firewalld.getServiceSettings(serviceName);
    }

    /**
     * FirewallD主接口
     */
    @DBusInterfaceName("org.fedoraproject.FirewallD1")
    interface FirewallDInterface extends DBusInterface {
        String getDefaultZone();
        String[] listServices();
        Object getServiceSettings(String service);
        Object getZoneSettings(String zone);
    }

    /**
     * FirewallD区域接口
     */
    @DBusInterfaceName("org.fedoraproject.FirewallD1.zone")
    interface FirewallDZoneInterface extends DBusInterface {
        String[] getZones();
        Map<String, Map<String, List<String>>> getActiveZones();
        String[] getServices(String zone);
        String[][] getPorts(String zone);
        String[][] getSourcePorts(String zone);
        String[] getProtocols(String zone);
        String[] getInterfaces(String zone);
        String[] getSources(String zone);
        String[] getRichRules(String zone);
        String[][] getForwardPorts(String zone);
        boolean queryMasquerade(String zone);
        String[] getIcmpBlocks(String zone);
        boolean queryIcmpBlockInversion(String zone);
    }

    /**
     * FirewallD直接规则接口
     */
    @DBusInterfaceName("org.fedoraproject.FirewallD1.direct")
    interface FirewallDDirectInterface extends DBusInterface {
        Object[] getAllChains();
        Object[] getAllRules();
        Object[] getAllPassthroughs();
    }

    /**
     * FirewallD IPSet接口
     */
    @DBusInterfaceName("org.fedoraproject.FirewallD1.ipset")
    interface FirewallDIPSetInterface extends DBusInterface {
        String[] getIPSets();
        Object getIPSetSettings(String ipset);
        String[] getEntries(String ipset);
    }
    
    /**
     * 打印所有FirewallD规则的主方法
     */
    public void printAllFirewallDRules() throws IOException {
        try {
            
            // 获取FirewallD基本信息
            Map<String, Object> info = getFirewallDInfo();
            System.out.println("=== FirewallD 信息 ===");
            System.out.println("版本: " + info.get("version"));
            System.out.println("状态: " + info.get("state"));
            System.out.println("接口版本: " + info.get("interface_version"));
            System.out.println("IPv4支持: " + info.get("IPv4"));
            System.out.println("IPv6支持: " + info.get("IPv6"));
            System.out.println();
            
            // 获取默认区域
            String defaultZone = getDefaultZone();
            System.out.println("默认区域: " + defaultZone);
            System.out.println();
            
            // 获取所有区域
            List<String> zones = getZones();
            System.out.println("=== 区域列表 ===");
            for (String zone : zones) {
                System.out.println("- " + zone);
            }
            System.out.println();
            
            // 获取活动区域及其接口
            Map<String, Map<String, List<String>>> activeZones = getActiveZones();
            System.out.println("=== 活动区域 ===");
            for (Map.Entry<String, Map<String, List<String>>> entry : activeZones.entrySet()) {
                System.out.println("区域: " + entry.getKey());
                Map<String, List<String>> zoneDetails = entry.getValue();
                
                for (Map.Entry<String, List<String>> detail : zoneDetails.entrySet()) {
                    System.out.println("  " + detail.getKey() + ": " + detail.getValue());
                }
            }
            System.out.println();
            
            // 获取每个区域的详细配置
            System.out.println("=== 区域详细配置 ===");
            for (String zone : zones) {
                System.out.println("区域: " + zone + (zone.equals(defaultZone) ? " (默认)" : ""));
                Map<String, Object> zoneConfig = getZoneConfig(zone);
                
                System.out.println("  服务: " + Arrays.toString((String[]) zoneConfig.get("services")));
                System.out.println("  端口: " + Arrays.deepToString((String[][]) zoneConfig.get("ports")));
                System.out.println("  源端口: " + Arrays.deepToString((String[][]) zoneConfig.get("sourcePorts")));
                System.out.println("  协议: " + Arrays.toString((String[]) zoneConfig.get("protocols")));
                System.out.println("  接口: " + Arrays.toString((String[]) zoneConfig.get("interfaces")));
                System.out.println("  源地址: " + Arrays.toString((String[]) zoneConfig.get("sources")));
                System.out.println("  富规则: " + Arrays.toString((String[]) zoneConfig.get("richRules")));
                System.out.println("  转发端口: " + Arrays.deepToString((String[][]) zoneConfig.get("forwardPorts")));
                System.out.println("  伪装: " + zoneConfig.get("masquerade"));
                System.out.println("  ICMP阻止: " + Arrays.toString((String[]) zoneConfig.get("icmpBlocks")));
                System.out.println("  ICMP阻止反转: " + zoneConfig.get("icmpBlockInversion"));
                System.out.println();
            }
            
            // 获取直接规则
            Map<String, Object> directRules = getDirectRules();
            System.out.println("=== 直接规则 ===");
            System.out.println("链: " + Arrays.toString((Object[]) directRules.get("chains")));
            System.out.println("规则: " + Arrays.toString((Object[]) directRules.get("rules")));
            System.out.println("直通规则: " + Arrays.toString((Object[]) directRules.get("passthroughs")));
            System.out.println();
            
            // 获取IPSet信息
            Map<String, Object> ipsetInfo = getIPSets();
            System.out.println("=== IPSet 配置 ===");
            String[] ipsets = (String[]) ipsetInfo.get("ipsets");
            Map<String, Object> ipsetDetails = (Map<String, Object>) ipsetInfo.get("details");
            
            for (String ipset : ipsets) {
                System.out.println("IPSet: " + ipset);
                Map<String, Object> details = (Map<String, Object>) ipsetDetails.get(ipset);
                System.out.println("  设置: " + details.get("settings"));
                System.out.println("  条目: " + Arrays.toString((String[]) details.get("entries")));
                System.out.println();
            }

        } catch (DBusException e) {
            System.err.println("Error connecting to FirewallD: " + e.getMessage());
            e.printStackTrace();
        } finally {
            // 关闭连接
            disconnect();
        }
    }

    /**
     * 示例用法
     */
    public static void main(String[] args) throws IOException, DBusException {
        FirewallDRuleQuery query = new FirewallDRuleQuery();
        query.printAllFirewallDRules();

    }
}
