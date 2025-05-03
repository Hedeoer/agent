package cn.hedeoer.firewalld.firewalld.op;

import java.util.*;

public class FlexibleRichRule {
    // 保存规则组件的主列表，保持顺序
    private List<RuleComponent> components = new ArrayList<>();
    
    // 规则组件抽象类
    public abstract static class RuleComponent {
        public abstract String toRuleString();
    }
    
    // 简单组件 - 如family或单独的action
    public static class SimpleComponent extends RuleComponent {
        private String name;
        private String value;
        private boolean isValueQuoted = true;
        
        public SimpleComponent(String name, String value) {
            this.name = name;
            this.value = value;
        }
        
        public SimpleComponent(String name, String value, boolean isValueQuoted) {
            this.name = name;
            this.value = value;
            this.isValueQuoted = isValueQuoted;
        }
        
        public String getName() {
            return name;
        }
        
        public String getValue() {
            return value;
        }
        
        @Override
        public String toRuleString() {
            if (value == null) {
                return name;  // 用于无值组件如accept, drop等
            }
            return name + (isValueQuoted ? "=\"" + value + "\"" : "=" + value);
        }
    }
    
    // 复合组件 - 如source address="x.x.x.x", port port="80" protocol="tcp"
    public static class CompositeComponent extends RuleComponent {
        private String name;
        private Map<String, String> attributes = new LinkedHashMap<>();
        private boolean isNot = false; // 用于支持"NOT"修饰符
        
        public CompositeComponent(String name) {
            this.name = name;
        }
        
        public CompositeComponent(String name, boolean isNot) {
            this.name = name;
            this.isNot = isNot;
        }
        
        public String getName() {
            return name;
        }
        
        public Map<String, String> getAttributes() {
            return attributes;
        }
        
        public boolean isNot() {
            return isNot;
        }
        
        public void setNot(boolean not) {
            isNot = not;
        }
        
        public void addAttribute(String key, String value) {
            attributes.put(key, value);
        }
        
        @Override
        public String toRuleString() {
            StringBuilder sb = new StringBuilder(name);
            
            if (isNot) {
                sb.append(" NOT");
            }
            
            for (Map.Entry<String, String> entry : attributes.entrySet()) {
                sb.append(" ").append(entry.getKey())
                  .append("=\"").append(entry.getValue()).append("\"");
            }
            
            return sb.toString();
        }
    }
    
    // 添加简单组件
    public void addSimpleComponent(String name, String value) {
        components.add(new SimpleComponent(name, value));
    }
    
    // 添加无值组件
    public void addFlagComponent(String name) {
        components.add(new SimpleComponent(name, null));
    }
    
    // 添加复合组件
    public CompositeComponent createCompositeComponent(String name) {
        CompositeComponent component = new CompositeComponent(name);
        components.add(component);
        return component;
    }
    
    // 添加复合组件(带NOT修饰符)
    public CompositeComponent createCompositeComponent(String name, boolean isNot) {
        CompositeComponent component = new CompositeComponent(name, isNot);
        components.add(component);
        return component;
    }
    
    // 添加现有组件
    public void addComponent(RuleComponent component) {
        components.add(component);
    }
    
    // 获取所有组件
    public List<RuleComponent> getComponents() {
        return components;
    }
    
    // 转换为富规则字符串
    public String toRichRuleString() {
        StringBuilder sb = new StringBuilder("rule");
        
        for (RuleComponent component : components) {
            sb.append(" ").append(component.toRuleString());
        }
        
        return sb.toString();
    }
    
    // 从字符串解析富规则的完整实现
    public static FlexibleRichRule parse(String ruleString) {
        FlexibleRichRule rule = new FlexibleRichRule();
        
        // 移除开头的"rule"关键字(如果存在)并去除首尾空格
        String normalizedRule = ruleString.trim();
        if (normalizedRule.toLowerCase().startsWith("rule")) {
            normalizedRule = normalizedRule.substring(4).trim();
        }
        
        // 预处理: 保护引号内的空格，以便于后续分割
        normalizedRule = protectQuotedSpaces(normalizedRule);
        
        // 解析各个组件
        parseComponents(rule, normalizedRule);
        
        return rule;
    }
    
    // 保护引号内的空格
    private static String protectQuotedSpaces(String input) {
        StringBuilder result = new StringBuilder();
        boolean inQuotes = false;
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            
            if (c == '"') {
                inQuotes = !inQuotes;
                result.append(c);
            } else if (c == ' ' && inQuotes) {
                // 在引号内的空格临时替换为特殊字符
                result.append("␣");
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }
    
    // 恢复受保护的空格
    private static String restoreProtectedSpaces(String input) {
        return input.replace("␣", " ");
    }
    
    // 解析组件
    private static void parseComponents(FlexibleRichRule rule, String normalizedRule) {
        // 富规则关键词列表
        Set<String> knownFlagComponents = new HashSet<>(Arrays.asList(
            "accept", "reject", "drop", "mark", "masquerade"
        ));
        
        Set<String> knownCompositeComponents = new HashSet<>(Arrays.asList(
            "source", "destination", "service", "port", "protocol", 
            "icmp-block", "icmp-type", "forward-port", "log", "audit", "limit"
        ));
        
        // 分割规则字符串为组件
        List<String> tokens = tokenizeRule(normalizedRule);
        int index = 0;
        
        while (index < tokens.size()) {
            String token = tokens.get(index);
            
            // 处理family属性
            if (token.startsWith("family=")) {
                String value = extractValue(token);
                rule.addSimpleComponent("family", value);
                index++;
                continue;
            }
            
            // 处理复合组件
            boolean isComposite = false;
            for (String componentName : knownCompositeComponents) {
                if (token.equals(componentName)) {
                    boolean isNot = false;
                    
                    // 检查是否有NOT修饰符
                    if (index + 1 < tokens.size() && tokens.get(index + 1).equals("NOT")) {
                        isNot = true;
                        index++;
                    }
                    
                    CompositeComponent component = rule.createCompositeComponent(componentName, isNot);
                    
                    // 收集该组件的所有属性
                    index++;
                    while (index < tokens.size() && 
                           !knownFlagComponents.contains(tokens.get(index)) && 
                           !knownCompositeComponents.contains(tokens.get(index))) {
                        
                        String attrToken = tokens.get(index);
                        int equalsPos = attrToken.indexOf('=');
                        
                        if (equalsPos > 0) {
                            String attrName = attrToken.substring(0, equalsPos);
                            String attrValue = extractValue(attrToken.substring(equalsPos));
                            component.addAttribute(attrName, attrValue);
                        }
                        
                        index++;
                    }
                    
                    isComposite = true;
                    break;
                }
            }
            
            if (isComposite) {
                continue;
            }
            
            // 处理标志组件(无值组件)
            if (knownFlagComponents.contains(token)) {
                rule.addFlagComponent(token);
                index++;
                continue;
            }
            
            // 处理reject类型
            if (token.equals("reject") && index + 1 < tokens.size() && 
                tokens.get(index + 1).startsWith("type=")) {
                
                CompositeComponent reject = rule.createCompositeComponent("reject");
                index++;
                String typeValue = extractValue(tokens.get(index));
                reject.addAttribute("type", typeValue);
                index++;
                continue;
            }
            
            // 处理mark
            if (token.equals("mark") && index + 1 < tokens.size() && 
                tokens.get(index + 1).startsWith("set=")) {
                
                CompositeComponent mark = rule.createCompositeComponent("mark");
                index++;
                String setValue = extractValue(tokens.get(index));
                mark.addAttribute("set", setValue);
                index++;
                continue;
            }
            
            // 处理未知的键值对
            if (token.contains("=")) {
                int equalsPos = token.indexOf('=');
                String name = token.substring(0, equalsPos);
                String value = extractValue(token.substring(equalsPos));
                rule.addSimpleComponent(name, value);
                index++;
                continue;
            }
            
            // 无法识别的令牌，作为单独的组件添加
            rule.addFlagComponent(token);
            index++;
        }
    }
    
    // 将规则分割成令牌序列
    private static List<String> tokenizeRule(String normalizedRule) {
        List<String> tokens = new ArrayList<>();
        StringBuilder currentToken = new StringBuilder();
        boolean inToken = false;
        
        for (int i = 0; i < normalizedRule.length(); i++) {
            char c = normalizedRule.charAt(i);
            
            if (c == ' ') {
                if (inToken) {
                    tokens.add(currentToken.toString());
                    currentToken = new StringBuilder();
                    inToken = false;
                }
            } else {
                currentToken.append(c);
                inToken = true;
            }
        }
        
        // 添加最后一个令牌
        if (inToken) {
            tokens.add(currentToken.toString());
        }
        
        // 恢复所有值中受保护的空格
        for (int i = 0; i < tokens.size(); i++) {
            tokens.set(i, restoreProtectedSpaces(tokens.get(i)));
        }
        
        return tokens;
    }
    
    // 从键值对中提取值
    private static String extractValue(String token) {
        // 处理形如 name="value" 或 name=value 的格式
        int equalsPos = token.indexOf('=');
        if (equalsPos < 0) return "";
        
        String value = token.substring(equalsPos + 1).trim();
        
        // 如果值被引号包围，去除引号
        if (value.startsWith("\"") && value.endsWith("\"")) {
            value = value.substring(1, value.length() - 1);
        }
        
        return value;
    }
    
    @Override
    public String toString() {
        return toRichRuleString();
    }
    
    // 辅助方法：查找特定类型的组件
    public RuleComponent findComponent(String name) {
        for (RuleComponent component : components) {
            if ((component instanceof SimpleComponent && 
                 ((SimpleComponent) component).getName().equals(name)) ||
                (component instanceof CompositeComponent && 
                 ((CompositeComponent) component).getName().equals(name))) {
                return component;
            }
        }
        return null;
    }
    
    // 辅助方法：查找所有特定类型的组件
    public List<RuleComponent> findAllComponents(String name) {
        List<RuleComponent> result = new ArrayList<>();
        for (RuleComponent component : components) {
            if ((component instanceof SimpleComponent && 
                 ((SimpleComponent) component).getName().equals(name)) ||
                (component instanceof CompositeComponent && 
                 ((CompositeComponent) component).getName().equals(name))) {
                result.add(component);
            }
        }
        return result;
    }
    
    // 删除组件
    public boolean removeComponent(String name) {
        Iterator<RuleComponent> iterator = components.iterator();
        while (iterator.hasNext()) {
            RuleComponent component = iterator.next();
            if ((component instanceof SimpleComponent && 
                 ((SimpleComponent) component).getName().equals(name)) ||
                (component instanceof CompositeComponent && 
                 ((CompositeComponent) component).getName().equals(name))) {
                iterator.remove();
                return true;
            }
        }
        return false;
    }
}
