package cn.hedeoer.pojo;

import cn.hedeoer.util.AgentIdUtil;
import lombok.*;

/**
 * 端口信息实体类
 */
@Getter
@Setter
@EqualsAndHashCode
@Builder
@ToString
public class PortInfo {
    private String agentId;          // agent节点的唯一标识
    private String protocol;         // 协议
    private Integer portNumber;          // 端口号
    private String processName;      // 进程名
    private Integer processId;           // 进程ID
    private String commandLine;      // 完整命令行
    private String listenAddress;    // 监听地址
    private String family;           // 监听的ipv4 or ipv6


    // 每个PortInfo对象的agentId是唯一的
    public PortInfo(String agentId,String protocol, Integer portNumber, String processName, Integer processId, String commandLine, String listenAddress,String family) {
        this.agentId = AgentIdUtil.loadOrCreateUUID();
        this.protocol = protocol;
        this.portNumber = portNumber;
        this.processName = processName;
        this.processId = processId;
        this.commandLine = commandLine;
        this.listenAddress = listenAddress;
        this.family = family;
    }

    public PortInfo() {
        this.agentId = AgentIdUtil.loadOrCreateUUID();
    }



    // Helper method to determine information completeness
    public Integer gainInfoCompletenessScore() {
        int score = 0;
        if(family != null && !family.isEmpty()) score += 3;
        if(protocol != null && !protocol.isEmpty()) score += 3;
        if (processName != null && !processName.isEmpty()) score += 2;
        if (commandLine != null && !commandLine.isEmpty()) score += 2;
        if (listenAddress != null && !listenAddress.equals("unknown")) score += 1;
        if (processId > 0) score += 1;
        return score;
    }
}