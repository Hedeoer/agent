package cn.hedeoer.pojo;

/**
 * 防火墙枚举，支持 ufw， firewalld
 */
public enum FireWallType {

    UFW("ufw")
    , FIREWALLD("firewalld")
    ;
    private String fireWallType;

    FireWallType(String firewalld) {
        this.fireWallType = firewalld;
    }

    public String getFireWallType() {
        return fireWallType;
    }

    public void setFireWallType(String fireWallType) {
        this.fireWallType = fireWallType;
    }
}
