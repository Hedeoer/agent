package cn.hedeoer.firewalld.op;

import cn.hedeoer.firewalld.PortRule;
import org.freedesktop.dbus.annotations.DBusInterfaceName;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.interfaces.DBusInterface;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class PortRuleServiceImpl implements PortRuleService {
    @Override
    public List<PortRule> queryAllPortRule(String zoneName) {
        ArrayList<PortRule> portRules = new ArrayList<>();
        try {
            // 首先判断zone是否存在

            // 查询zone下所有端口信息
            DBusConnection dBusConnection = FirewallDRuleQuery.getDBusConnection();

            // 获取firewalld服务的对象
            String serviceName = "org.fedoraproject.FirewallD1";
            String zonePath = "/org/fedoraproject/FirewallD1/zone/public";
            // 获取Zone对象
            ZoneInterface zoneInterface = dBusConnection.getRemoteObject(serviceName, zonePath, ZoneInterface.class);
            portRules = getPortRule(zoneInterface);
        } catch (DBusException e) {
            throw new RuntimeException(e);
        }

        return portRules;
    }

    private ArrayList<PortRule> getPortRule(ZoneInterface zoneInterface) {
        // 获取所有端口配置
        List<List<String>> ports = zoneInterface.getPorts();
        // 获取富规则（用于获取更详细的配置）
        List<Map<String, Object>> richRules = zoneInterface.getRichRules();
        // 处理获取的端口信息
        for (List<String> portInfo : ports) {
            String portWithProtocol = portInfo.get(0); // 格式如 "8080/tcp"
            String[] parts = portWithProtocol.split("/");

            String portNumber = parts[0];
            String protocol = parts[1];

            // 检查端口状态
            boolean enabled = zoneInterface.queryPort(portNumber, protocol);

            System.out.println("端口: " + portNumber);
            System.out.println("协议: " + protocol);
            System.out.println("状态: " + (enabled ? "开启" : "关闭"));

            // 默认策略通常是放行(accept)，除非在富规则中被修改
            String policy = "accept";

            // 从富规则中查找与此端口相关的规则
            String sourceIP = "";
            String description = "";

            for (Map<String, Object> rule : richRules) {
                // 检查规则是否与当前端口相关
                if (rule.containsKey("port") && rule.get("port").toString().contains(portNumber + "/" + protocol)) {
                    if (rule.containsKey("source")) {
                        sourceIP = rule.get("source").toString();
                    }
                    if (rule.containsKey("action")) {
                        policy = rule.get("action").toString(); // 可能是accept或reject
                    }
                    if (rule.containsKey("log") && ((Map) rule.get("log")).containsKey("prefix")) {
                        description = ((Map) rule.get("log")).get("prefix").toString();
                    }
                }
            }

            System.out.println("策略: " + policy);
            System.out.println("源IP: " + (sourceIP.isEmpty() ? "任何" : sourceIP));
            System.out.println("描述: " + (description.isEmpty() ? "无" : description));
            System.out.println("---------------------------");
        }
    }

    @DBusInterfaceName("org.fedoraproject.FirewallD1.zone")
    interface ZoneInterface extends DBusInterface {
        // 获取所有端口
        List<List<String>> getPorts();

        // 获取特定端口的信息
        boolean queryPort(String port, String protocol);

        // 获取区域的规则
        List<Map<String, Object>> getRichRules();
    }
}
