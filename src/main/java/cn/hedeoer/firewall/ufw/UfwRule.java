package cn.hedeoer.firewall.ufw;

import cn.hedeoer.util.IpUtils; // 假设 IpUtils.isIpv6(String ip) 方法有效
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * UFW 防火墙规则对象
 * 表示一条从 'ufw status numbered' 命令输出中解析得到的防火墙规则。
 * 包含规则编号、目标、动作、方向、来源、注释、IPv6状态和启用状态。
 */
public class UfwRule {
    private int ruleNumber = -1;
    private String to;
    private String action;
    private String direction;
    private String from;
    private String comment;
    private boolean isIpv6;
    private boolean enabled;

    private static final Pattern NUMBERED_RULE_PATTERN = Pattern.compile("^\\[\\s*(\\d+)\\]\\s*(.*)");

    // 核心正则表达式，应用于清理后的 rulePart (已移除 (v6), (out), (in) 等标记)
    // 捕获组:
    // 1: To
    // 2: Action (可能是 Action+Direction)
    // 3: Direction (可选, 如果 Action 和 Direction 分开)
    // 4: From
    private static final Pattern CORE_RULE_PATTERN =
            Pattern.compile("^(\\S+)\\s{2,}(\\S+)(?:\\s+(\\S+))?\\s{2,}(\\S+)\\s*$");

    // 备用三列结构 "To Action From"
    private static final Pattern THREE_COLUMN_PATTERN =
            Pattern.compile("^(\\S+)\\s{2,}(\\S+)\\s{2,}(\\S+)\\s*$");

    // 检查端口格式，用于辅助判断 "To" 字段是否为 IP
    private static final Pattern NUMERIC_PORT_PATTERN = Pattern.compile("^\\d+(:\\d+)?(/\\w+)?$");


    public UfwRule() {
    }

    public static UfwRule parseFromStatus(String rawLine) {
        if (rawLine == null || rawLine.trim().isEmpty() ||
                rawLine.contains("--") ||
                (rawLine.contains("To") && rawLine.contains("Action") && rawLine.contains("From"))) {
            return null;
        }

        UfwRule rule = new UfwRule();
        String lineToParse = rawLine.trim();

        // 1. 解析并移除规则编号
        Matcher numberedMatcher = NUMBERED_RULE_PATTERN.matcher(lineToParse);
        if (numberedMatcher.find()) {
            try {
                rule.ruleNumber = Integer.parseInt(numberedMatcher.group(1));
            } catch (NumberFormatException e) {
                System.err.println("警告: 无法从行中解析规则编号: " + lineToParse);
                rule.ruleNumber = -1;
            }
            lineToParse = numberedMatcher.group(2).trim();
        }

        // 2. 检查规则是否被禁用
        if (lineToParse.toLowerCase(Locale.ROOT).contains("[disabled]")) {
            rule.enabled = false;
            lineToParse = lineToParse.replaceAll("(?i)\\[disabled\\]", "").trim();
        } else {
            rule.enabled = true;
        }

        // 3. 分离注释
        String rulePart;
        int commentStartIndex = -1;
        boolean inQuotes = false;
        for (int i = 0; i < lineToParse.length(); i++) {
            char c = lineToParse.charAt(i);
            if (c == '"' || c == '\'') {
                inQuotes = !inQuotes;
            } else if (c == '#' && !inQuotes) {
                commentStartIndex = i;
                break;
            }
        }
        if (commentStartIndex != -1) {
            rulePart = lineToParse.substring(0, commentStartIndex).trim();
            rule.comment = lineToParse.substring(commentStartIndex + 1).trim();
        } else {
            rulePart = lineToParse;
            rule.comment = null;
        }

        // 4. 预处理 rulePart: 移除末尾的 (out) 或 (in) 标记，并记录全局 (v6) 标记
        // 这些标记通常是 ufw status 的视觉提示，不是核心规则定义
        // 注意：移除 (out)/(in) 应该在检查 (v6) 之后，或者确保不互相干扰
        // 顺序：先检查 (v6)，然后移除 (out)/(in)，再移除 (v6) 以便简化核心正则
        boolean rulePartHadGlobalV6Marker = rulePart.contains("(v6)");

        // 移除末尾的 (out) 或 (in) 标记，这些通常是状态输出的额外提示
        // Pattern for trailing (out) or (in) with optional surrounding spaces
        rulePart = rulePart.replaceAll("\\s*\\((out|in)\\)\\s*$", "").trim();
        // 处理孟加拉语或其他可能的本地化 "in" 标记（如果ufw会本地化这些）
        // 这是一个示例，实际中可能需要更全面的本地化处理或配置ufw以英文输出
        rulePart = rulePart.replaceAll("\\s*\\(\\s*(?:ইন| ইন)\\s*\\)\\s*$", "").trim();


        // 创建一个清理过的规则部分，移除所有 "(v6)" 标记，以简化后续的正则匹配和列分割
        String cleanedRulePart = rulePart.replaceAll("\\(v6\\)", "").trim();

        // 5. 解析核心规则字段
        boolean parsedSuccessfully = false;
        Matcher coreMatcher = CORE_RULE_PATTERN.matcher(cleanedRulePart);

        if (coreMatcher.find()) {
            rule.to = coreMatcher.group(1).trim();
            String actionOrActionDirection = coreMatcher.group(2).trim();
            String explicitDirection = coreMatcher.group(3);
            rule.from = coreMatcher.group(4).trim();

            if (explicitDirection != null && !explicitDirection.trim().isEmpty()) {
                rule.action = actionOrActionDirection;
                rule.direction = explicitDirection.trim();
            } else {
                parseActionDirection(rule, actionOrActionDirection);
            }
            parsedSuccessfully = true;
        } else {
            Matcher threeColMatcher = THREE_COLUMN_PATTERN.matcher(cleanedRulePart);
            if (threeColMatcher.find()) {
                rule.to = threeColMatcher.group(1).trim();
                parseActionDirection(rule, threeColMatcher.group(2).trim());
                rule.from = threeColMatcher.group(3).trim();
                parsedSuccessfully = true;
            } else {
                String[] columns = splitByMultipleSpaces(cleanedRulePart);
                if (columns.length >= 3) {
                    rule.to = columns[0];
                    String actionCandidate = columns[1];
                    if (columns.length >= 4) {
                        rule.action = actionCandidate;
                        rule.direction = columns[2];
                        rule.from = columns[3];
                    } else {
                        rule.from = columns[2];
                        parseActionDirection(rule, actionCandidate);
                    }
                    parsedSuccessfully = true;
                }
            }
        }

        if (!parsedSuccessfully) {
            System.err.println("无法解析UFW规则行: " + rawLine + " (处理后规则部分: " + cleanedRulePart + ")");
            return null;
        }

        // 6. 标准化 action 和 direction
        if (rule.action != null) rule.action = rule.action.toUpperCase(Locale.ROOT);
        if (rule.direction != null) {
            rule.direction = rule.direction.toUpperCase(Locale.ROOT);
        } else if ("LIMIT".equals(rule.action)) {
            rule.direction = "IN";
        }

        // 7. 确定是否为 IPv6 规则
        rule.isIpv6 = rulePartHadGlobalV6Marker; // 首先检查原始规则部分是否有 (v6) 标记
        if (!rule.isIpv6) {
            // 检查 'From' 字段是否为明确的 IPv6 地址
            if (rule.from != null && !isSpecialAddress(rule.from) &&
                    IpUtils.isIpv6(stripCidr(rule.from))) {
                rule.isIpv6 = true;
            }
        }
        if (!rule.isIpv6) {
            // 检查 'To' 字段是否为明确的 IPv6 地址 (且不是端口)
            if (rule.to != null && !isSpecialAddress(rule.to) &&
                    !NUMERIC_PORT_PATTERN.matcher(stripCidr(rule.to)).matches() && // 确保 'To' 不是一个端口/服务名
                    IpUtils.isIpv6(stripCidr(rule.to))) {
                rule.isIpv6 = true;
            }
        }


        // 确保关键字段不为 null
        if (rule.action == null || rule.action.isEmpty()) {
            System.err.println("解析错误: Action 字段为空。原始行: " + rawLine);
            return null;
        }
        if (rule.from == null || rule.from.isEmpty()) rule.from = "Anywhere";
        if (rule.to == null || rule.to.isEmpty()) {
            // 'To' 字段通常是端口/服务。如果为空，可能表示 'Anywhere' 或解析问题。
            // ufw 通常不允许 'To' 为空，除非 'Action' 是 'default' (这里不处理 default 规则)
            // 对于 ALLOW/DENY/REJECT/LIMIT，'To' 应该是端口或 'Anywhere'。
            // 如果 'To' 字段解析为空，且不是 'default' 规则，可能需要特殊处理或标记为错误
            // 暂时假设 'Anywhere' 如果解析为空（尽管 ufw status 通常会明确写出 'Anywhere'）
            rule.to = "Anywhere";
            System.err.println("警告: 'To' 字段为空，默认为 'Anywhere'。原始行: " + rawLine);
        }


        return rule;
    }

    private static void parseActionDirection(UfwRule rule, String actionCandidate) {
        actionCandidate = actionCandidate.trim();
        if (actionCandidate.endsWith("IN") && actionCandidate.length() > 2 && Character.isUpperCase(actionCandidate.charAt(actionCandidate.length()-3))) {
            rule.action = actionCandidate.substring(0, actionCandidate.length() - 2).trim();
            rule.direction = "IN";
        } else if (actionCandidate.endsWith("OUT") && actionCandidate.length() > 3 && Character.isUpperCase(actionCandidate.charAt(actionCandidate.length()-4))) {
            rule.action = actionCandidate.substring(0, actionCandidate.length() - 3).trim();
            rule.direction = "OUT";
        } else {
            rule.action = actionCandidate;
            if ("LIMIT".equalsIgnoreCase(rule.action)) {
                rule.direction = "IN";
            } else {
                rule.direction = null; // Direction 未知
            }
        }
    }

    private static String[] splitByMultipleSpaces(String line) {
        if (line == null) return new String[0];
        return line.trim().split("\\s{2,}");
    }

    private static String stripCidr(String address) {
        if (address == null) return null;
        int slashIndex = address.indexOf('/');
        if (slashIndex != -1) {
            return address.substring(0, slashIndex);
        }
        return address;
    }

    private static boolean isSpecialAddress(String address) {
        if (address == null) return false;
        String lowerAddr = address.toLowerCase(Locale.ROOT);
        return lowerAddr.equals("anywhere") || lowerAddr.equals("any");
    }

    // Getters (and potentially Setters)
    public int getRuleNumber() { return ruleNumber; }
    public String getTo() { return to; }
    public String getAction() { return action; }
    public String getDirection() { return direction; }
    public String getFrom() { return from; }
    public String getComment() { return comment; }
    public boolean isIpv6() { return isIpv6; }
    public boolean isEnabled() { return enabled; }

    // Key for comparing core functional equivalence (cleaned port, action, cleaned source)
    public String getCoreEquivalenceKey() {
        return (this.to == null ? "null" : this.to) + "#" +
                (this.action == null ? "null" : this.action) + "#" +
                (this.from == null ? "null" : this.from);
    }

    @Override
    public String toString() {
        return "UfwRule{" +
                "ruleNumber=" + ruleNumber +
                ", to='" + to + '\'' +
                ", action='" + action + '\'' +
                ", direction='" + direction + '\'' +
                ", from='" + from + '\'' +
                (comment != null ? ", comment='" + comment + '\'' : "") +
                ", isIpv6=" + isIpv6 +
                ", enabled=" + enabled +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UfwRule ufwRule = (UfwRule) o;
        return ruleNumber == ufwRule.ruleNumber &&
                isIpv6 == ufwRule.isIpv6 &&
                enabled == ufwRule.enabled &&
                Objects.equals(to, ufwRule.to) &&
                Objects.equals(action, ufwRule.action) &&
                Objects.equals(direction, ufwRule.direction) &&
                Objects.equals(from, ufwRule.from) &&
                Objects.equals(comment, ufwRule.comment);
    }

    @Override
    public int hashCode() {
        return Objects.hash(ruleNumber, to, action, direction, from, comment, isIpv6, enabled);
    }
}