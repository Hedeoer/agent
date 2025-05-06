package cn.hedeoer.firewall.ufw;

import cn.hedeoer.util.IpUtils;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.ArrayList;
import java.util.List;

/**
 * UFW 防火墙规则
 * 表示单条防火墙规则，包含端口/协议、动作、方向、来源/目标和注释
 */
public class UfwRule {
    private String to;          // 目标端口/协议
    private String action;      // 动作 (ALLOW, DENY, REJECT, LIMIT)
    private String direction;   // 方向 (IN, OUT)
    private String from;        // 来源
    private String comment;     // 注释
    private boolean isIpv6;     // 是否为 IPv6 规则
    private boolean enabled;    // 规则是否启用

    /**
     * 从 UFW 状态输出格式解析规则
     * 这种格式通常有固定的列宽和对齐方式
     * @param line 单行规则文本
     * @return 解析后的 UfwRule 对象，如果无法解析则返回 null
     */
    public static UfwRule parseFromStatus(String line) {
        // 忽略表头行和分隔行
        if (line == null || line.trim().isEmpty() ||
                line.contains("--") || line.contains("To") && line.contains("Action") && line.contains("From")) {
            return null;
        }

        UfwRule rule = new UfwRule();

        // 检查规则是否启用
        rule.enabled = !line.contains("[disabled]") && !line.contains("[DISABLED]");

        rule.isIpv6 = line.contains("(v6)");

        // 移除状态指示符
        line = line.replaceAll("\\[\\w+\\]", "").trim();


        // 分离注释部分 (处理注释中可能包含的 # 字符)
        int commentIndex = -1;
        boolean inQuotes = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"' || c == '\'') {
                inQuotes = !inQuotes;
            } else if (c == '#' && !inQuotes) {
                commentIndex = i;
                break;
            }
        }

        String rulePart;
        if (commentIndex != -1) {
            rulePart = line.substring(0, commentIndex).trim();
            rule.comment = line.substring(commentIndex + 1).trim();
        } else {
            rulePart = line;
        }

        // 使用正则表达式匹配 UFW 状态输出的格式
        // 尝试多种可能的格式模式

        // 模式1: 标准的三列格式 (To Action Direction From)
        Pattern pattern1 = Pattern.compile("^(\\S+(?:\\s+\\(v6\\))?)\\s{2,}(\\S+)\\s+(\\S+)\\s{2,}(.+?)\\s*$");
        Matcher matcher1 = pattern1.matcher(rulePart);

        // 模式2: 紧凑格式 (To ActionDirection From)
        Pattern pattern2 = Pattern.compile("^(\\S+(?:\\s+\\(v6\\))?)\\s{2,}(\\S+)(IN|OUT)\\s{2,}(.+?)\\s*$");
        Matcher matcher2 = pattern2.matcher(rulePart);

        if (matcher1.find()) {
            rule.to = matcher1.group(1).replace("(v6)", "").trim();
            rule.action = matcher1.group(2);
            rule.direction = matcher1.group(3);
            rule.from = matcher1.group(4).replace("(v6)", "").trim();
        } else if (matcher2.find()) {
            rule.to = matcher2.group(1).replace("(v6)", "").trim();
            rule.action = matcher2.group(2);
            rule.direction = matcher2.group(3);
            rule.from = matcher2.group(4).replace("(v6)", "").trim();
        } else {
            // 尝试更宽松的解析方法
            String[] columns = splitIntoColumns(rulePart);
            if (columns.length >= 3) {
                rule.to = columns[0].replace("(v6)", "").trim();

                // 处理可能合并的 Action 和 Direction
                String actionDirection = columns[1];
                if (actionDirection.endsWith("IN") || actionDirection.endsWith("OUT")) {
                    rule.direction = actionDirection.substring(actionDirection.length() - 2);
                    rule.action = actionDirection.substring(0, actionDirection.length() - 2).trim();
                } else {
                    // 假设第二列是 Action，第三列是 Direction
                    rule.action = columns[1];
                    rule.direction = columns[2];
                }

                // From 是剩余的部分
                if (columns.length > 3) {
                    rule.from = columns[columns.length - 1].replace("(v6)", "").trim();
                } else {
                    rule.from = "Anywhere" + (rule.isIpv6 ? " (v6)" : "");
                }
            } else {
                // 无法解析
                return null;
            }
        }

        // 检查是否为 IPv6 规则
        // 22 (v6)                    ALLOW IN    Anywhere (v6)
        // 8102/tcp                   ALLOW IN    2001:db8::/64              # Explicitly IPv6 rule
        // ufw对于 source来源模糊的规则，比如Anywhere，不清晰是适用于ipv4还是ipv6，给出(v6)字样明确标识
        // ufw对于 可以通过source来源明确的规则，比如2001:db8::/64，清晰是适用于ipv6，不给出(v6)字样
        boolean isIpv6 = false;
        if (line.contains("(v6)")) {
            isIpv6 = true;
        }else if (!rule.from.contains("Anywhere")) {
            isIpv6 = IpUtils.isIpv6(rule.from);
        }
        rule.setIpv6(isIpv6);

        // 标准化 Action (有时可能包含额外的空格或小写字母)
        if (rule.action != null) {
            rule.action = rule.action.toUpperCase().trim();
        }

        // 标准化 Direction
        if (rule.direction != null) {
            rule.direction = rule.direction.toUpperCase().trim();
        }

        return rule;
    }

    /**
     * 将规则行分割成列，考虑到 UFW 输出中的固定宽度列
     */
    private static String[] splitIntoColumns(String line) {
        List<String> columns = new ArrayList<>();
        StringBuilder currentColumn = new StringBuilder();
        boolean inWhitespace = false;
        int consecutiveSpaces = 0;

        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);

            if (Character.isWhitespace(c)) {
                consecutiveSpaces++;
                if (consecutiveSpaces >= 2 && !inWhitespace && currentColumn.length() > 0) {
                    // 发现列分隔符 (连续两个或更多空格)
                    columns.add(currentColumn.toString().trim());
                    currentColumn = new StringBuilder();
                    inWhitespace = true;
                }
            } else {
                consecutiveSpaces = 0;
                inWhitespace = false;
                currentColumn.append(c);
            }
        }

        // 添加最后一列
        if (currentColumn.length() > 0) {
            columns.add(currentColumn.toString().trim());
        }

        return columns.toArray(new String[0]);
    }

    /**
     * 将规则转换为 UFW 命令格式
     * @return 可用于 ufw 命令的规则字符串
     */
    public String toUfwCommand() {
        StringBuilder command = new StringBuilder("ufw ");

        if (!enabled) {
            command.append("--dry-run ");
        }

        command.append(action.toLowerCase()).append(" ");

        if (direction.equalsIgnoreCase("IN")) {
            command.append("from ").append(from).append(" to any port ").append(to);
        } else if (direction.equalsIgnoreCase("OUT")) {
            command.append("from any to ").append(from).append(" port ").append(to);
        }

        if (comment != null && !comment.isEmpty()) {
            command.append(" comment '").append(comment).append("'");
        }

        return command.toString();
    }

    // Getters and setters
    public String getTo() {
        return to;
    }

    public void setTo(String to) {
        this.to = to;
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    public String getDirection() {
        return direction;
    }

    public void setDirection(String direction) {
        this.direction = direction;
    }

    public String getFrom() {
        return from;
    }

    public void setFrom(String from) {
        this.from = from;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public boolean isIpv6() {
        return isIpv6;
    }

    public void setIpv6(boolean ipv6) {
        isIpv6 = ipv6;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();

        if (!enabled) {
            sb.append("[DISABLED] ");
        }

        sb.append(to);
        if (isIpv6) {
            sb.append(" (v6)");
        }
        sb.append("\t");

        sb.append(action).append(" ").append(direction).append("\t");
        sb.append(from);
        if (isIpv6 && from.equals("Anywhere")) {
            sb.append(" (v6)");
        }

        if (comment != null && !comment.isEmpty()) {
            sb.append("\t# ").append(comment);
        }

        return sb.toString();
    }
}