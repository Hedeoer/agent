package cn.hedeoer.pojo;

import lombok.*;

/**
 * 端口信息实体类
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@ToString
public class PortInfo {
    private String protocol;         // 协议
    private Integer portNumber;          // 端口号
    private String processName;      // 进程名
    private Integer processId;           // 进程ID
    private String commandLine;      // 完整命令行
    private String listenAddress;    // 监听地址

    // Helper method to determine information completeness
    public Integer getInfoCompletenessScore() {
        int score = 0;
        if(protocol != null && !protocol.isEmpty()) score += 3;
        if (processName != null && !processName.isEmpty()) score += 2;
        if (commandLine != null && !commandLine.isEmpty()) score += 2;
        if (listenAddress != null && !listenAddress.equals("unknown")) score += 1;
        if (processId > 0) score += 1;
        return score;
    }
}