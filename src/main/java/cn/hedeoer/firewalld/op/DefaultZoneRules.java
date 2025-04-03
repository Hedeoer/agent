package cn.hedeoer.firewalld.op;

import org.freedesktop.dbus.annotations.DBusInterfaceName;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.connections.impl.DBusConnectionBuilder;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.interfaces.DBusInterface;
import org.freedesktop.dbus.types.DBusStructType;
import org.freedesktop.dbus.types.Variant;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DefaultZoneRules {
    @DBusInterfaceName("org.fedoraproject.FirewallD1")
    public interface Firewalld extends DBusInterface {
        String getDefaultZone();
        ZoneStruct getZoneSettings(String zone);
    }


    public static void main(String[] args) {
        Map<String, Object> rules = getFirewalldRules();
        if (rules != null) {
            System.out.println("Firewalld规则:");
            rules.forEach((key, value) -> System.out.println(key + ": " + value));
        } else {
            System.err.println("获取Firewalld规则失败");
        }
    }

    // 首先定义所需的结构体类型
    public static class ZoneStruct extends DBusStructType {
        public final String version;           // s: version
        public final String name;              // s: name
        public final String description;       // s: description
        public final boolean target_present;   // b: target_present
        public final String target;            // s: target
        public final List<String> services;    // as: services
        public final List<PortProtocolStruct> ports; // a(ss): ports
        public final List<String> icmpBlocks;  // as: icmp_blocks
        public final boolean masquerade;       // b: masquerade
        public final List<ForwardPortStruct> forwardPorts; // a(ssss): forward_ports
        public final List<String> interfaces;  // as: interfaces
        public final List<String> sources;     // as: sources
        public final List<String> rules;       // as: rules_str
        public final List<String> protocols;   // as: protocols
        public final List<SourcePortStruct> sourceports; // a(ss): source_ports
        public final boolean icmp_block_inversion; // b: icmp_block_inversion

        public ZoneStruct(String version, String name, String description,
                          boolean target_present, String target, List<String> services,
                          List<PortProtocolStruct> ports, List<String> icmpBlocks,
                          boolean masquerade, List<ForwardPortStruct> forwardPorts,
                          List<String> interfaces, List<String> sources, List<String> rules,
                          List<String> protocols, List<SourcePortStruct> sourceports,
                          boolean icmp_block_inversion) {
            super();
            this.version = version;
            this.name = name;
            this.description = description;
            this.target_present = target_present;
            this.target = target;
            this.services = services;
            this.ports = ports;
            this.icmpBlocks = icmpBlocks;
            this.masquerade = masquerade;
            this.forwardPorts = forwardPorts;
            this.interfaces = interfaces;
            this.sources = sources;
            this.rules = rules;
            this.protocols = protocols;
            this.sourceports = sourceports;
            this.icmp_block_inversion = icmp_block_inversion;
        }
    }

    public static class PortProtocolStruct extends DBusStructType {
        public final String port;
        public final String protocol;

        public PortProtocolStruct(String port, String protocol) {
            super();
            this.port = port;
            this.protocol = protocol;
        }

        @Override
        public String toString() {
            return port + "/" + protocol;
        }
    }

    public static class ForwardPortStruct extends DBusStructType {
        public final String port;
        public final String protocol;
        public final String toport;
        public final String toaddr;

        public ForwardPortStruct(String port, String protocol, String toport, String toaddr) {
            super();
            this.port = port;
            this.protocol = protocol;
            this.toport = toport;
            this.toaddr = toaddr;
        }

        @Override
        public String toString() {
            return port + "/" + protocol + " to " +
                    (toaddr.isEmpty() ? "" : toaddr + ":") +
                    (toport.isEmpty() ? port : toport);
        }
    }

    public static class SourcePortStruct extends DBusStructType {
        public final String port;
        public final String protocol;

        public SourcePortStruct(String port, String protocol) {
            super();
            this.port = port;
            this.protocol = protocol;
        }

        @Override
        public String toString() {
            return port + "/" + protocol;
        }
    }

    public static Map<String, Object> getFirewalldRules() {
        try {
            // 连接到DBus系统总线
            DBusConnection connection = DBusConnectionBuilder.forSystemBus().build();

            // 获取FirewallD远程对象
            Firewalld firewalld = connection.getRemoteObject(
                    "org.fedoraproject.FirewallD1",
                    "/org/fedoraproject/FirewallD1",
                    Firewalld.class
            );

            // 获取默认区域
            String defaultZone = firewalld.getDefaultZone();

            // 获取默认区域的详细设置
            ZoneStruct zoneSettings = firewalld.getZoneSettings(defaultZone);

            // 将结果转换为Map
            Map<String, Object> settings = new HashMap<>();
            settings.put("defaultZone", defaultZone);
            settings.put("name", zoneSettings.name);
            settings.put("description", zoneSettings.description);
            settings.put("target", zoneSettings.target);
            settings.put("services", zoneSettings.services);
            settings.put("ports", zoneSettings.ports);
            settings.put("icmpBlocks", zoneSettings.icmpBlocks);
            settings.put("masquerade", zoneSettings.masquerade);
            settings.put("forwardPorts", zoneSettings.forwardPorts);
            settings.put("interfaces", zoneSettings.interfaces);
            settings.put("sources", zoneSettings.sources);
            settings.put("protocols", zoneSettings.protocols);
            settings.put("sourceports", zoneSettings.sourceports);
            settings.put("icmpBlockInversion", zoneSettings.icmp_block_inversion);

            connection.close();
            return settings;

        } catch (DBusException e) {
            e.printStackTrace();
            System.err.println("DBus错误: " + e.getMessage());
            return null;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
