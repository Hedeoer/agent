package cn.hedeoer.pojo;

import cn.hedeoer.common.enmu.FireWallStatus;
import cn.hedeoer.common.enmu.FireWallType;
import cn.hedeoer.common.enmu.PingStatus;
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
    private FireWallType firewallType;

    /** 防火墙运行状态（running/active/disabled/not installed/unknown） */
    private FireWallStatus status;

    /** 防火墙版本号 */
    private String version;

    /** 是否禁ping */
    private PingStatus pingDisabled;

    /** 获取时间戳 */
    private Long timestamp;
}