package cn.hedeoer.firewalld.op;

import cn.hedeoer.firewalld.PortRule;
import cn.hedeoer.firewalld.exception.FirewallException;

import java.util.List;

/**
 * 某个zone下的端口规则操作
 */
public interface PortRuleService {
    /**
     * 查询 某个zone下的所有端口信息
     * @param zoneName zone名字
     * @return 端口信息列表
     */
    List<PortRule> queryAllPortRule(String zoneName);

    /**
     * 添加一条端口规则
     * @param portRule 端口规则
     * @param zoneName zone名字
     * @param  operation portRule operation (insert or delete)
     * @return 添加结果
     */
    Boolean addOrRemovePortRule(String zoneName, PortRule portRule, String operation) throws FirewallException;
}
