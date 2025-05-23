package cn.hedeoer.common.entity;

import cn.hedeoer.common.enmu.RuleType;
import lombok.Data;

/**
 * 抽象基类，实现共享属性和方法
 */
@Data
public abstract class AbstractFirewallRule implements FirewallRule {
    protected String zone;        // 区域名称
    protected RuleType type;      // 规则类型
    protected boolean permanent;  // 是否永久规则
    protected String agentId;    // 所属节点ID
}
