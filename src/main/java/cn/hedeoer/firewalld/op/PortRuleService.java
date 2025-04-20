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
     * 添加或者移除一条端口规则
     * @param portRule 端口规则
     * @param zoneName zone名字
     * @param  operation portRule operation (insert or delete)
     * @return 添加或者移除结果 需要由调用方根据返回值判断是否要加载firewalld使其 addOrRemoveOnePortRule 生效
     */
    Boolean addOrRemoveOnePortRule(String zoneName, PortRule portRule, String operation) throws FirewallException;


    /**
     * 批量添加或者移除端口规则
     * @param zoneName
     * @param portRules
     * @param operation
     * @return 都成功 返回true，否则 false ;需要由调用方根据返回值判断是否要加载firewalld使其 addOrRemoveBatchPortRules 生效
     */
    Boolean addOrRemoveBatchPortRules(String zoneName, List<PortRule> portRules, String operation) throws FirewallException;


    /**
     * 通过 端口使用状态查询端口规则
     * @param zoneName
     * @param isUsing false 表示端口未使用
     * @return 端口规则列表
     */
    List<PortRule> queryPortRulesByUsingStatus(String zoneName, Boolean isUsing);

    /**
     * 通过 规则策略 查询端口规则
     * @param zoneName
     * @param policy false 表示端口该端口规则为拒绝
     * @return 端口规则列表
     */
    List<PortRule> queryPortRulesByPolicy(String zoneName, Boolean policy);

    /**
     * 通过 规则策略 和 端口使用状态 查询端口规则
     * @param zoneName
     * @param isUsing
     * @param policy
     * @return
     */
    List<PortRule> queryPortRulesByPolicyAndUsingStatus(String zoneName, Boolean isUsing , Boolean policy);

    /**
     * 更新一个端口规则
     * @param zoneName
     * @param oldPortRule
     * @param newPortRule
     * @return 更新成功则 true; 需要由调用方根据返回值判断是否要加载firewalld使其 updateOnePortRule 生效
     */
    Boolean updateOnePortRule(String zoneName, PortRule oldPortRule,PortRule newPortRule) throws FirewallException;

}
