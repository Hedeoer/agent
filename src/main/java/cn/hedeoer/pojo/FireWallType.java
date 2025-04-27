package cn.hedeoer.pojo;

/**
 * 防火墙枚举，支持 ufw， firewalld
 */
public enum FireWallType {
    UFW("ufw"),
    FIREWALLD("firewalld");

    private final String firewallType;

    FireWallType(String firewallType) {
        this.firewallType = firewallType;
    }

    public String getFirewallType() {
        return firewallType;
    }
}
