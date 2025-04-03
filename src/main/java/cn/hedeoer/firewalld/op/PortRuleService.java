package cn.hedeoer.firewalld.op;

import cn.hedeoer.firewalld.PortRule;

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
}
