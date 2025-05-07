package cn.hedeoer.firewall.ufw;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
     * @param verboseOutput UFW status verbose 命令的输出 (用于解析总体状态)
     * @param numberedOutput UFW status numbered 命令的输出 (用于解析规则)
     * @return 解析后的 UfwStatus 对象
     */
    public static UfwStatus parse(String verboseOutput, String numberedOutput) {
        UfwStatus status = new UfwStatus();

        // 1. 解析来自 "ufw status verbose" 的总体状态信息
        String[] verboseLines = verboseOutput.split("\n");
        for (String line : verboseLines) {
            String trimmedLine = line.trim(); // 去除行首尾空格
            if (trimmedLine.startsWith("Status:")) {
                status.active = trimmedLine.contains("active");
            } else if (trimmedLine.startsWith("Logging:")) {
                // 原始逻辑: Logging: on (low)
                // 有些系统可能输出: Logging: low (on)
                Pattern loggingPattern = Pattern.compile("Logging:\\s+(?:on|off)?\\s*\\(([^)]+)\\)|Logging:\\s+([^\\s(]+)(?:\\s*\\((on|off)\\))?");
                Matcher loggingMatcher = loggingPattern.matcher(trimmedLine);
                if (loggingMatcher.find()) {
                    if (loggingMatcher.group(1) != null) { // 匹配 on (level)
                        status.loggingLevel = loggingMatcher.group(1).trim();
                    } else if (loggingMatcher.group(2) != null) { // 匹配 level (on/off)
                        status.loggingLevel = loggingMatcher.group(2).trim();
                        // String loggingState = matcher.group(3); // 'on' or 'off', 可以选择性保存
                    }
                }
            } else if (trimmedLine.startsWith("Default:")) {
                Pattern pattern = Pattern.compile("Default:\\s*(\\w+)\\s*\\(incoming\\),\\s*(\\w+)\\s*\\(outgoing\\),\\s*(\\w+)\\s*\\(routed\\)");
                Matcher matcher = pattern.matcher(trimmedLine);
                if (matcher.find()) {
                    status.defaultIncoming = matcher.group(1);
                    status.defaultOutgoing = matcher.group(2);
                    status.defaultRouted = matcher.group(3);
                }
            } else if (trimmedLine.startsWith("New profiles:")) {
                status.newProfiles = trimmedLine.substring("New profiles:".length()).trim();
            }
            // 注意：此处不再解析规则行，规则将从 numberedOutput 解析
        }

        // 2. 解析来自 "ufw status numbered" 的规则列表
        String[] numberedLines = numberedOutput.split("\n");
        boolean rulesSectionStarted = false; // 标记是否已开始解析规则

        for (String line : numberedLines) {
            String trimmedLine = line.trim();
            if (trimmedLine.isEmpty()) {
                continue;
            }

            // "ufw status numbered" 输出通常包含一个表头 "To Action From"
            // 和一个分隔行 "--- ------ ----"
            // 我们需要跳过这些非规则行，以及可能存在的状态行
            if (trimmedLine.startsWith("To") && trimmedLine.contains("Action") && trimmedLine.contains("From")) {
                rulesSectionStarted = true; // 遇到表头，标记规则部分开始
                continue; // 跳过表头行
            }
            if (rulesSectionStarted && trimmedLine.matches("^-+.*")) { // 匹配分隔行，如 "--- --- ----"
                continue; // 跳过分隔行
            }

            // 如果已经进入规则区域，并且行看起来像一条规则（通常以数字或 '[数字]' 开头）
            // `UfwRule.parseFromStatus` 应该能处理具体的规则格式
            if (rulesSectionStarted) {
                // 检查行是否以数字或方括号加数字开头，这是 numbered output 规则行的典型特征
                // 例如: "[ 1] 22/tcp ALLOW IN Anywhere" 或 "1 22/tcp ALLOW IN Anywhere"
                if (trimmedLine.matches("^\\[\\s*\\d+\\s*\\]\\s+.*") || trimmedLine.matches("^\\d+\\s+.*")) {
                    UfwRule rule = UfwRule.parseFromStatus(trimmedLine);
                    if (rule != null) {
                        status.rules.add(rule);
                    }
                }
            }
            // 对于 `numberedOutput` 中的其他行（如 Status: active），我们忽略它们，因为总体状态已从 `verboseOutput` 解析
        }

        return status;
    }

    // Getters and setters
    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public String getLoggingLevel() {
        return loggingLevel;
    }

    public void setLoggingLevel(String loggingLevel) {
        this.loggingLevel = loggingLevel;
    }

    public String getDefaultIncoming() {
        return defaultIncoming;
    }

    public void setDefaultIncoming(String defaultIncoming) {
        this.defaultIncoming = defaultIncoming;
    }

    public String getDefaultOutgoing() {
        return defaultOutgoing;
    }

    public void setDefaultOutgoing(String defaultOutgoing) {
        this.defaultOutgoing = defaultOutgoing;
    }

    public String getDefaultRouted() {
        return defaultRouted;
    }

    public void setDefaultRouted(String defaultRouted) {
        this.defaultRouted = defaultRouted;
    }

    public String getNewProfiles() {
        return newProfiles;
    }

    public void setNewProfiles(String newProfiles) {
        this.newProfiles = newProfiles;
    }

    public List<UfwRule> getRules() {
        return rules;
    }

    public void setRules(List<UfwRule> rules) {
        this.rules = rules;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Status: ").append(active ? "active" : "inactive").append("\n");
        if (loggingLevel != null && !loggingLevel.isEmpty()) {
            sb.append("Logging: on (").append(loggingLevel).append(")\n"); // 假设总是 'on' 如果有 level
        } else {
            sb.append("Logging: off\n"); // 或者根据实际情况调整
        }
        sb.append("Default: ");
        sb.append(defaultIncoming != null ? defaultIncoming : "unknown").append(" (incoming), ");
        sb.append(defaultOutgoing != null ? defaultOutgoing : "unknown").append(" (outgoing), ");
        sb.append(defaultRouted != null ? defaultRouted : "unknown").append(" (routed)\n");
        if (newProfiles != null && !newProfiles.isEmpty()) {
            sb.append("New profiles: ").append(newProfiles).append("\n");
        }
        sb.append("\n");

        // 规则输出可以保持与 numbered output 类似的格式，或者自定义
        // 这里我们假设 UfwRule.toString() 会给出合适的规则表示
        if (rules != null && !rules.isEmpty()) {
            sb.append("To                         Action      From\n"); // 示例表头
            sb.append("--                         ------      ----\n");
            for (UfwRule rule : rules) {
                sb.append(rule.toString()).append("\\n"); // 假设 UfwRule 有这样的方法
            }
        } else {
            sb.append("No rules found.\n");
        }

        return sb.toString();
    }
}

