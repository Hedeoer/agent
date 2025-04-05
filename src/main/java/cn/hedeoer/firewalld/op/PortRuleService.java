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
     * @return 添加或者移除结果
     */
    Boolean addOrRemovePortRule(String zoneName, PortRule portRule, String operation) throws FirewallException;

    /**
     * 多个端口，如：8080,8081 意味着多次执行单个端口规则的操作 firewall-cmd --zone=public --add-port=8080/tcp --add-port=8081/tcp  --permanent
     * 添加或者移除多条端口规则
     * @param zoneName
     * @param portRules
     * @param operation
     * @return  添加或者移除
     */
    Boolean addOrRemovePortRuleByMultiPort(String zoneName, List<PortRule> portRules, String operation) throws FirewallException;
}
