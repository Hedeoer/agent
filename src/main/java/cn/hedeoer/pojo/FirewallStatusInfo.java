package cn.hedeoer.pojo;

import lombok.Builder;
import lombok.Data;
import lombok.ToString;

@Data
@ToString
@Builder
public class FirewallStatusInfo {
    /** 机器唯一标识 */
    private String agentId;

    /** 防火墙类型（FIREWALLD、UFW、NONE） */
    private String firewallType;

    /** 防火墙运行状态（running/active/disabled/not installed/unknown） */
    private String status;

    /** 防火墙版本号 */
    private String version;

    /** 是否禁ping */
    private Boolean pingDisabled;

    /** 获取时间戳 */
    private Long timestamp;
}