package cn.hedeoer.firewalld.ufw;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * UFW 防火墙状态解析器
 * 适用于 UFW 版本 0.36.2
 */
public class UfwStatus {
    // 防火墙总体状态
    private boolean active;
    private String loggingLevel;
    private String defaultIncoming;
    private String defaultOutgoing;
    private String defaultRouted;
    private String newProfiles;
    
    // 规则列表
    private List<UfwRule> rules;
    
    public UfwStatus() {
        this.rules = new ArrayList<>();
    }
    
    /**
     * 从 UFW 状态输出文本解析状态
     * @param output UFW status verbose 命令的输出
     * @return 解析后的 UfwStatus 对象
     */
    public static UfwStatus parse(String output) {
        UfwStatus status = new UfwStatus();
        
        // 分割输出为行
        String[] lines = output.split("\n");
        
        // 解析状态部分
        for (String line : lines) {
            if (line.startsWith("Status:")) {
                status.active = line.contains("active");
            } else if (line.startsWith("Logging:")) {
                String[] parts = line.split("\\(");
                if (parts.length > 1) {
                    status.loggingLevel = parts[1].replace(")", "").trim();
                }
            } else if (line.startsWith("Default:")) {
                Pattern pattern = Pattern.compile("Default: (\\w+) \\(incoming\\), (\\w+) \\(outgoing\\), (\\w+) \\(routed\\)");
                Matcher matcher = pattern.matcher(line);
                if (matcher.find()) {
                    status.defaultIncoming = matcher.group(1);
                    status.defaultOutgoing = matcher.group(2);
                    status.defaultRouted = matcher.group(3);
                }
            } else if (line.startsWith("New profiles:")) {
                status.newProfiles = line.substring("New profiles:".length()).trim();
            } else if (line.matches("^\\d+.*|^[\\w/]+.*")) {
                // 规则行，跳过表头行
                if (!line.startsWith("To") && !line.trim().isEmpty()) {
                    UfwRule rule = UfwRule.parseFromStatus(line);
                    if (rule != null) {
                        status.rules.add(rule);
                    }
                }
            }
        }
        
        return status;
    }
    
    // Getters and setters
    public boolean isActive() {
        return active;
    }
    
    public String getLoggingLevel() {
        return loggingLevel;
    }
    
    public String getDefaultIncoming() {
        return defaultIncoming;
    }
    
    public String getDefaultOutgoing() {
        return defaultOutgoing;
    }
    
    public String getDefaultRouted() {
        return defaultRouted;
    }
    
    public String getNewProfiles() {
        return newProfiles;
    }
    
    public List<UfwRule> getRules() {
        return rules;
    }
    
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Status: ").append(active ? "active" : "inactive").append("\n");
        sb.append("Logging: on (").append(loggingLevel).append(")\n");
        sb.append("Default: ").append(defaultIncoming).append(" (incoming), ")
          .append(defaultOutgoing).append(" (outgoing), ")
          .append(defaultRouted).append(" (routed)\n");
        sb.append("New profiles: ").append(newProfiles).append("\n\n");
        
        sb.append("To\tAction\tFrom\tComment\n");
        for (UfwRule rule : rules) {
            sb.append(rule).append("\n");
        }
        
        return sb.toString();
    }
}