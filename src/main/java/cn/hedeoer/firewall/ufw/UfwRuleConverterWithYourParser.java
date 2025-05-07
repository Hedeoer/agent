package cn.hedeoer.firewall.ufw;

import cn.hedeoer.util.IpUtils; // 你的 IpUtils 包名
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zeroturnaround.exec.ProcessExecutor;
import org.zeroturnaround.exec.ProcessResult;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * UFW规则转换器，用于将UFW (Uncomplicated Firewall) 的通用规则转换为更详细的、区分协议的规则。
 * 主要功能包括：
 * 1. 将不指定协议的端口规则（如 "allow 80"）分解为针对TCP和UDP的单独规则
 *    （如 "allow 80/tcp" 和 "allow 80/udp"）。
 * 2. 在上述转换后，清理可能因此变得多余的通用IPv6规则。
 *
 * <p>此工具通过执行 {@code ufw} 命令来读取和修改规则，因此需要相应的sudo权限。
 * 它首先解析 {@code ufw status numbered} 的输出，然后根据定义的逻辑删除旧规则并添加新规则。</p>
 *
 * <p><b>注意：</b>此脚本修改防火墙规则，请在理解其工作原理和潜在影响后谨慎使用。
 * 强烈建议在测试环境中首先验证其行为。</p>
 */
public class UfwRuleConverterWithYourParser {
    private static final Logger logger = LoggerFactory.getLogger(UfwRuleConverterWithYourParser.class);

    // --- UfwRule 类 ---
    /**
     * 表示从 {@code ufw status numbered} 命令输出中解析出的一条UFW规则。
     * 包含规则的各个组成部分，如编号、目标、动作、来源、方向、注释等。
     * 同时提供了将原始输出行解析为UfwRule对象的方法。
     * 实现 {@link Comparable} 接口以便按规则编号排序。
     */
    public static class UfwRule implements Comparable<UfwRule> {
        /** 规则编号, 从 `ufw status numbered` 输出中解析得到。如果解析失败或不适用，则为-1。 */
        private int ruleNumber = -1;
        /** 清理后的目标 (例如 "80", "22/tcp", "Anywhere", "ssh")。不包含 (v6) 标记。 */
        private String to;
        /** 从 `ufw status numbered` 输出中原始的目标字段字符串，可能包含 (v6) 等标记。 */
        private String rawTo;
        /** 规则的动作 (例如 "ALLOW", "DENY", "REJECT", "LIMIT")，已转换为大写。 */
        private String action;
        /** 规则的方向 ("IN", "OUT")，已转换为大写。如果未明确指定，可能为null或根据动作推断（如LIMIT默认为IN）。 */
        private String direction;
        /** 清理后的来源 (例如 "192.168.1.0/24", "Anywhere")。不包含 (v6) 标记。 */
        private String from;
        /** 从 `ufw status numbered` 输出中原始的来源字段字符串，可能包含 (v6) 等标记。 */
        private String rawFrom;
        /** 规则的注释内容 (位于 '#' 之后的部分)。 */
        private String comment;
        /** 标记此规则是否为IPv6规则。 */
        private boolean isIpv6;
        /** 标记此规则是否启用。{@code true} 表示启用，{@code false} 表示被禁用 (含有 "[disabled]" 标记)。 */
        private boolean enabled;
        /**
         * 标记目标(To)字段是否已明确指定了协议或是一个服务名。
         * 例如 "80/tcp" 或 "ssh" 会使此项为 true。
         * "80" (纯数字端口) 或 "Anywhere" 会使此项为 false。
         */
        private boolean isProtocolSpecific;

        /** 用于匹配带编号的规则行的正则表达式，例如 "[ 1] ..." */
        private static final Pattern NUMBERED_RULE_PATTERN = Pattern.compile("^\\[\\s*(\\d+)\\]\\s*(.*)");
        /**
         * 用于匹配核心规则部分的标准正则表达式 (To Action [Direction] From)。
         * 捕获组: 1=To, 2=Action或ActionDirection, 3=可选的Direction, 4=From。
         */
        private static final Pattern CORE_RULE_PATTERN = Pattern.compile("^(\\S+)\\s{2,}(\\S+)(?:\\s+(\\S+))?\\s{2,}(\\S+)\\s*$");
        /** 用于匹配三列规则的正则表达式 (To ActionDirection From)，例如 "Anywhere ALLOWIN Anywhere"。 */
        private static final Pattern THREE_COLUMN_PATTERN = Pattern.compile("^(\\S+)\\s{2,}(\\S+)\\s{2,}(\\S+)\\s*$");
        /** 用于检查IPv6时，判断 "To" 字段是否为数字端口（可能带范围或协议）的模式，以避免将服务名误判为IPv6地址。 */
        private static final Pattern NUMERIC_PORT_PATTERN_FOR_IPV6_CHECK = Pattern.compile("^\\d+(:\\d+)?(/\\w+)?$");


        /**
         * 默认构造函数。
         */
        public UfwRule() {}

        /**
         * 从 {@code ufw status numbered} 的单行输出中解析UFW规则。
         *
         * @param rawLine {@code ufw status numbered} 命令输出的一行字符串。
         * @return 解析成功则返回 {@link UfwRule} 对象，否则返回 {@code null} (例如，对于表头、空行或无法解析的行)。
         *
         * <p>解析逻辑步骤：</p>
         * <ol>
         *   <li>预处理：去除首尾空格。</li>
         *   <li>过滤无效行：跳过表头、状态行、分隔符行等。</li>
         *   <li>提取规则编号：从 "[ 1]" 这样的格式中提取。如果无编号格式，则认为无效。</li>
         *   <li>检查禁用状态：查找并移除 "[disabled]" 标记，设置 {@link #enabled} 属性。</li>
         *   <li>提取注释：分离规则主体和 '#' 之后的注释，存入 {@link #comment}。注意处理引号内的'#'。</li>
         *   <li>初步清理规则主体：移除行尾的 "(v6)", "(in)", "(out)", "(ইন)", "( ইন)" 等方向或版本标记。记录是否存在全局的 "(v6)" 标记。</li>
         *   <li>核心规则解析：使用正则表达式匹配 "To Action [Direction] From" 或 "To ActionDirection From" 结构。
         *     <ul>
         *       <li>优先使用 {@link #CORE_RULE_PATTERN}。</li>
         *       <li>若不匹配，尝试 {@link #THREE_COLUMN_PATTERN}。</li>
         *       <li>若仍不匹配，尝试使用 {@link #splitByMultipleSpaces(String)} 按多个空格分割。</li>
         *     </ul>
         *     如果均无法解析出基本结构，则认为无效。
         *   </li>
         *   <li>最终化To和From字段：移除内部的 "(v6)" 标记，得到 {@link #to} 和 {@link #from}。</li>
         *   <li>确定 {@link #isProtocolSpecific}：根据 {@link #rawTo} 是否包含协议分隔符("/")或是否为非数字的服务名来判断。</li>
         *   <li>特殊处理LIMIT动作：如果解析出的action是LIMIT，且rawTo以"LIMIT "开头，则从rawTo中移除此前缀，并重新评估isProtocolSpecific。</li>
         *   <li>标准化Action和Direction：转换为大写。如果Action是主要动作(ALLOW, DENY, REJECT, LIMIT)且Direction未解析出，则Direction默认为 "IN"。</li>
         *   <li>推断IPv6状态 ({@link #isIpv6})：综合考虑全局"(v6)"标记、From/To字段是否为IPv6地址（使用 {@link IpUtils#isIpv6(String)}，并排除特殊地址和纯端口）。</li>
         *   <li>有效性检查：确保Action字段不为空。From/To为空则设为 "Anywhere"。</li>
         * </ol>
         */
        public static UfwRule parseFromStatus(String rawLine) {
            String trimmedLine = rawLine == null ? "" : rawLine.trim();
            // 1 & 2. 预处理和过滤无效行
            if (trimmedLine.isEmpty() ||
                    trimmedLine.contains("--") || // 跳过分隔行 "---"
                    (trimmedLine.contains("To") && trimmedLine.contains("Action") && trimmedLine.contains("From")) || // 跳过表头
                    trimmedLine.toLowerCase().startsWith("status:") ||
                    trimmedLine.toLowerCase().startsWith("logging:") ||
                    trimmedLine.toLowerCase().startsWith("default:") ||
                    trimmedLine.toLowerCase().startsWith("new profiles:")) {
                return null;
            }

            UfwRule rule = new UfwRule();
            String lineToParse = trimmedLine;

            // 3. 提取规则编号
            Matcher numberedMatcher = NUMBERED_RULE_PATTERN.matcher(lineToParse);
            if (numberedMatcher.find()) {
                try {
                    rule.ruleNumber = Integer.parseInt(numberedMatcher.group(1));
                } catch (NumberFormatException e) {
                    // 通常 NUMBERED_RULE_PATTERN 保证了 group(1) 是数字，但也可能存在非常规的输出
                    System.err.println("警告(UfwRule): 无法从行中解析规则编号: " + lineToParse);
                    logger.warn("无法从行中解析规则编号: '{}'", lineToParse, e);
                    return null; // 视为无法解析
                }
                lineToParse = numberedMatcher.group(2).trim(); // 剩余部分
            } else {
                // 对于 `ufw status numbered` 的输出，规则行必须有编号
                // 如果没有，则认为这不是一条有效的规则信息行，或者格式不符合预期
                System.err.println("警告(UfwRule): 行沒有編號格式: " + rawLine);
                logger.warn("行不符合编号格式: '{}'", rawLine);
                return null;
            }

            // 4. 检查禁用状态
            if (lineToParse.toLowerCase(Locale.ROOT).contains("[disabled]")) {
                rule.enabled = false;
                lineToParse = lineToParse.replaceAll("(?i)\\[disabled\\]", "").trim();
            } else {
                rule.enabled = true;
            }

            // 5. 提取注释
            String rulePart; // 不含注释的规则部分
            int commentStartIndex = -1;
            boolean inQuotes = false; // 用于处理注释符在引号内的情况
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

            // 6. 初步清理规则主体 (v6, in, out 标记)
            boolean rulePartHadGlobalV6Marker = rulePart.contains("(v6)"); // 记录是否存在全局 (v6) 标记
            // 移除行尾的方向指示器，例如 (in), (out) 或者孟加拉语的 (ইন)
            // (?i) 使其不区分大小写，但考虑到孟加拉语字符，这里不加，依赖原始大小写
            rulePart = rulePart.replaceAll("\\s*\\((out|in|ইন| ইন)\\)\\s*$", "").trim();
            // 清理后的规则部分，用于核心解析，移除 (v6) 标记
            String cleanedRulePart = rulePart.replaceAll("\\(v6\\)", "").trim();


            // 7. 核心规则解析
            boolean parsedSuccessfully = false;
            Matcher coreMatcher = CORE_RULE_PATTERN.matcher(cleanedRulePart);
            if (coreMatcher.find()) {
                rule.rawTo = coreMatcher.group(1).trim();
                String actionOrActionDirection = coreMatcher.group(2).trim();
                String explicitDirection = coreMatcher.group(3); // 可能为 null
                rule.rawFrom = coreMatcher.group(4).trim();

                if (explicitDirection != null && !explicitDirection.trim().isEmpty()) {
                    rule.action = actionOrActionDirection;
                    rule.direction = explicitDirection.trim();
                } else {
                    // Action 和 Direction 可能合并在一起，例如 ALLOWIN
                    parseActionDirection(rule, actionOrActionDirection);
                }
                parsedSuccessfully = true;
            } else {
                Matcher threeColMatcher = THREE_COLUMN_PATTERN.matcher(cleanedRulePart);
                if (threeColMatcher.find()) {
                    rule.rawTo = threeColMatcher.group(1).trim();
                    parseActionDirection(rule, threeColMatcher.group(2).trim()); // 第二列是 ActionDirection
                    rule.rawFrom = threeColMatcher.group(3).trim();
                    parsedSuccessfully = true;
                } else {
                    // 作为最后的尝试，按多个空格分割
                    String[] columns = splitByMultipleSpaces(cleanedRulePart);
                    if (columns.length >= 3) { // 至少需要 To, Action, From
                        rule.rawTo = columns[0];
                        String actionCandidate = columns[1];
                        if (columns.length >= 4) { // To, Action, Direction, From
                            rule.action = actionCandidate;
                            rule.direction = columns[2];
                            rule.rawFrom = columns[3];
                        } else { // To, ActionDirection, From
                            rule.rawFrom = columns[2];
                            parseActionDirection(rule, actionCandidate);
                        }
                        parsedSuccessfully = true;
                    }
                }
            }

            if (!parsedSuccessfully) {
                System.err.println("无法解析UFW规则行(UfwRule): " + rawLine + " (处理后: " + cleanedRulePart + ")");
                logger.warn("无法解析UFW规则行: '{}' (处理后: '{}')", rawLine, cleanedRulePart);
                return null;
            }

            // 8. 最终化 To 和 From 字段 (移除内部的 (v6) 等)
            // rawTo/rawFrom 保留原始解析值，to/from 是进一步清理后的值
            rule.to = rule.rawTo.replaceAll("\\(v6\\)", "").trim();
            rule.from = rule.rawFrom.replaceAll("\\(v6\\)", "").trim();

            // 9. 确定 isProtocolSpecific
            // 条件：To 字段包含 '/' (如 80/tcp), 或者 To 字段是一个服务名 (非纯数字端口，非anywhere)
            rule.isProtocolSpecific = rule.rawTo.contains("/") ||
                    (rule.rawTo.toLowerCase().matches("^[a-zA-Z][a-zA-Z0-9_-]*$") && // 允许字母、数字、下划线、连字符作为服务名
                            !NUMERIC_PORT_PATTERN_FOR_IPV6_CHECK.matcher(rule.rawTo).matches() && // 确保它不是一个纯数字端口（可能带范围或协议）
                            !rule.rawTo.equalsIgnoreCase("anywhere")); // "anywhere" 不是特定协议


            // 10. 特殊处理LIMIT动作，有时LIMIT信息可能被错误地包含在To字段中
            if (rule.action != null && rule.action.equalsIgnoreCase("LIMIT") && rule.to.toUpperCase().startsWith("LIMIT ")) {
                // 如果 action 是 LIMIT，并且 to 字段以 "LIMIT " 开头，则从 to 中移除 "LIMIT "
                rule.to = rule.to.substring("LIMIT ".length()).trim();
                // 重新评估 isProtocolSpecific，因为 to 字段已更改
                rule.isProtocolSpecific = rule.to.contains("/") ||
                        (rule.to.toLowerCase().matches("^[a-zA-Z][a-zA-Z0-9_-]*$") &&
                                !NUMERIC_PORT_PATTERN_FOR_IPV6_CHECK.matcher(rule.to).matches() &&
                                !rule.to.equalsIgnoreCase("anywhere"));
            }


            // 11. 标准化Action和Direction, 并为主要动作推断IN方向
            if (rule.action != null) rule.action = rule.action.toUpperCase(Locale.ROOT);
            if (rule.direction != null) rule.direction = rule.direction.toUpperCase(Locale.ROOT);
            else if ("LIMIT".equals(rule.action) || "ALLOW".equals(rule.action) || "DENY".equals(rule.action) || "REJECT".equals(rule.action)) {
                // 对于主要动作，如果方向未解析出，则默认为IN
                // ufw status 输出中，IN 常常是隐式的
                if(rule.direction == null) rule.direction = "IN";
            }


            // 12. 推断IPv6状态
            rule.isIpv6 = rulePartHadGlobalV6Marker; // 首先基于全局 (v6) 标记
            // 如果 From 字段是 IPv6 地址 (且不是特殊地址如 "anywhere")
            if (!rule.isIpv6 && rule.from != null && !isSpecialAddress(rule.from) && IpUtils.isIpv6(stripCidr(rule.from))) {
                rule.isIpv6 = true;
            }
            // 如果 To 字段是 IPv6 地址 (且不是特殊地址、不是数字端口/服务名)
            // NUMERIC_PORT_PATTERN_FOR_IPV6_CHECK 用于避免将 "80/tcp" 或服务名 "http" 误判为IPv6地址的部分
            if (!rule.isIpv6 && rule.to != null && !isSpecialAddress(rule.to) &&
                    !NUMERIC_PORT_PATTERN_FOR_IPV6_CHECK.matcher(stripCidr(rule.to)).matches() && // 确保 To 不是一个数字端口/服务
                    IpUtils.isIpv6(stripCidr(rule.to))) {
                rule.isIpv6 = true;
            }


            // 13. 有效性检查和默认值
            if (rule.action == null || rule.action.isEmpty()) {
                System.err.println("解析错误(UfwRule): Action为空. 行: " + rawLine);
                logger.warn("解析错误: Action为空. 行: '{}'", rawLine);
                return null; // Action 是必需的
            }
            if (rule.from == null || rule.from.isEmpty()) rule.from = "Anywhere";
            if (rule.to == null || rule.to.isEmpty()) rule.to = "Anywhere";

            return rule;
        }

        /**
         * 辅助方法：解析可能合并在一起的Action和Direction字符串。
         * 例如，将 "ALLOWIN" 分解为 action="ALLOW", direction="IN"。
         * @param rule UfwRule对象，用于设置解析出的action和direction。
         * @param candidate 包含Action或ActionDirection的字符串。
         */
        private static void parseActionDirection(UfwRule rule, String candidate) {
            candidate = candidate.trim();
            // 检查是否以 "IN" 结尾 (长度大于2，首字母大写或以LIMIT开头，如 "ALLOWIN", "LIMITIN")
            if (candidate.endsWith("IN") && candidate.length() > 2 && (Character.isUpperCase(candidate.charAt(0)) || candidate.startsWith("LIMIT"))) {
                rule.action = candidate.substring(0, candidate.length() - 2).trim();
                rule.direction = "IN";
            }
            // 检查是否以 "OUT" 结尾 (长度大于3，首字母大写)
            else if (candidate.endsWith("OUT") && candidate.length() > 3 && Character.isUpperCase(candidate.charAt(0))) {
                rule.action = candidate.substring(0, candidate.length() - 3).trim();
                rule.direction = "OUT";
            } else {
                // 无法明确分离，则整个作为Action
                rule.action = candidate;
                // 特殊处理：如果动作是LIMIT且方向未定，则默认为IN
                if ("LIMIT".equalsIgnoreCase(rule.action)) {
                    rule.direction = "IN";
                }
                // 其他情况，如果无法确定方向，则保持direction为null
            }
        }
        /** 辅助方法：按两个或更多连续空格分割字符串。 */
        private static String[] splitByMultipleSpaces(String line) { return line == null ? new String[0] : line.trim().split("\\s{2,}"); }
        /** 辅助方法：移除IP地址或服务名后的CIDR后缀 (例如, "192.168.1.0/24" -> "192.168.1.0")。 */
        private static String stripCidr(String addr) { if(addr==null) return null; int i=addr.indexOf('/'); return i!=-1?addr.substring(0,i):addr; }
        /** 辅助方法：检查地址是否为特殊地址如 "anywhere" 或 "any"。 */
        private static boolean isSpecialAddress(String addr) { if(addr==null) return false; String l=addr.toLowerCase(); return l.equals("anywhere")||l.equals("any"); }

        // --- Getters ---
        public int getRuleNumber() { return ruleNumber; }
        public String getTo() { return to; }
        public String getRawTo() { return rawTo; }
        public String getAction() { return action; }
        public String getDirection() { return direction; }
        public String getFrom() { return from; }
        public String getRawFrom() { return rawFrom; }
        public String getComment() { return comment; }
        public boolean isIpv6() { return isIpv6; }
        public boolean isEnabled() { return enabled; }
        public boolean isProtocolSpecific() { return isProtocolSpecific; }

        /**
         * 生成一个核心等效键，用于比较不同规则（例如IPv4和IPv6版本）是否本质上指代同一条策略。
         * 通常基于 To, Action, From 字段。
         * @return 表示规则核心等效性的字符串键。
         */
        public String getCoreEquivalenceKey() { return (this.to == null ? "null" : this.to) + "#" + (this.action == null ? "null" : this.action) + "#" + (this.from == null ? "null" : this.from); }

        /**
         * 比较规则编号，用于排序。
         * @param other 另一个UfwRule对象。
         * @return 比较结果。
         */
        @Override public int compareTo(UfwRule other) { return Integer.compare(this.ruleNumber, other.ruleNumber); }

        @Override public String toString() { return String.format("[%d] rawTo:'%s' To:'%s' Act:'%s' Dir:'%s' rawFrom:'%s' From:'%s' IPv6:%b ProtoSpec:%b Comm:'%s' Enabled:%b", ruleNumber, rawTo, to, action, direction, rawFrom, from, isIpv6, isProtocolSpecific, comment, enabled); }
        @Override public boolean equals(Object o) { if (this == o) return true; if (o == null || getClass() != o.getClass()) return false; UfwRule r = (UfwRule) o; return ruleNumber == r.ruleNumber && isIpv6 == r.isIpv6 && enabled == r.enabled && Objects.equals(to, r.to) && Objects.equals(action, r.action) && Objects.equals(direction, r.direction) && Objects.equals(from, r.from) && Objects.equals(comment, r.comment) && isProtocolSpecific == r.isProtocolSpecific; }
        @Override public int hashCode() { return Objects.hash(ruleNumber, to, action, direction, from, comment, isIpv6, enabled, isProtocolSpecific); }
    }
    // --- UfwRule 类结束 ---


    /**
     * 执行UFW规则转换的核心方法。
     * 该方法分两个主要阶段执行：
     * <p><b>阶段 1: 主要规则转换</b></p>
     * <ul>
     *   <li>获取当前所有UFW规则 (通过 {@code sudo ufw status numbered})。</li>
     *   <li>筛选出符合条件的 "通用" 规则进行转换。这些规则通常是：
     *     <ul>
     *       <li>入站 (IN)</li>
     *       <li>动作为 ALLOW, DENY, 或 REJECT</li>
     *       <li>目标 (To) 字段未明确指定协议 (例如, "80" 而不是 "80/tcp")</li>
     *       <li>目标 (To) 字段是一个数字端口号</li>
     *       <li>规则已启用</li>
     *     </ul>
     *   </li>
     *   <li>对每个被选中的候选规则 (按规则编号从大到小处理，以避免删除导致编号错乱)：
     *     <ol>
     *       <li>首先通过规则编号删除原有的通用规则 ({@code sudo ufw --force delete <number>})。</li>
     *       <li>如果删除成功，则添加两条新的、明确协议的规则：一条TCP规则和一条UDP规则。
     *           例如，原规则 "allow in 80" 会被替换为 "allow in 80/tcp" 和 "allow in 80/udp"。
     *           如果原规则指定了来源 (From)，新规则也会保留来源。
     *       </li>
     *       <li>原规则的注释会尝试附加到新规则上。</li>
     *     </ol>
     *   </li>
     *   <li>记录下那些被成功转换的规则的核心信息 (基于To, Action, From的 {@link UfwRule#getCoreEquivalenceKey()})，
     *       这些信息将用于阶段2的IPv6规则清理。</li>
     * </ul>
     *
     * <p><b>阶段 2: 全局迭代清理多余的通用 IPv6 规则</b></p>
     * <ul>
     *   <li>此阶段旨在删除那些因为阶段1的转换而可能变得多余的通用IPv6规则。
     *       例如，如果 "ALLOW IN 80" (通常指IPv4或两者) 被转换为 "ALLOW IN 80/tcp" 和 "ALLOW IN 80/udp"
     *       (这些新规则通常会自动应用于IPv4和IPv6)，那么原先可能存在的、专门针对IPv6的通用规则
     *       "ALLOW IN 80 (v6)" 就可能变得多余。
     *   </li>
     *   <li>此清理过程会迭代进行，因为每次删除规则都可能改变后续规则的编号：
     *     <ol>
     *       <li>重新获取当前的UFW规则列表。</li>
     *       <li>查找符合以下条件的IPv6规则：
     *         <ul>
     *           <li>是IPv6规则 ({@link UfwRule#isIpv6()} 为 true)。</li>
     *           <li>方向为 IN，动作为 ALLOW, DENY, 或 REJECT。</li>
     *           <li>目标 (To) 未指定协议且为数字端口。</li>
     *           <li>其核心信息 ({@link UfwRule#getCoreEquivalenceKey()}) 与阶段1中已转换的某个规则的核心信息相匹配。
     *              这确保了只清理那些其IPv4对应版本已被分解的IPv6规则。
     *           </li>
     *           <li>规则已启用。</li>
     *         </ul>
     *       </li>
     *       <li>将找到的待删除IPv6规则按编号从大到小排序并逐个删除。</li>
     *     </ol>
     *   </li>
     *   <li>迭代会持续进行，直到在一轮迭代中没有规则被删除，或者达到预设的最大迭代次数 ({@code maxCleanupIterations})。</li>
     * </ul>
     *
     * @throws IOException 如果执行 {@code ufw} 命令或处理其输入/输出时发生I/O错误。
     * @throws InterruptedException 如果当前线程在等待 {@code ufw} 命令执行完成时被中断。
     * @throws TimeoutException 如果 {@code ufw} 命令执行时间超出预设的超时限制。
     */
    public static void covertUfwRuleToDetailStyle() throws IOException, InterruptedException, TimeoutException {
        Pattern numericPortPattern = Pattern.compile("^\\d+(:\\d+)?$"); // 匹配纯数字端口，可能带范围如 "60000:61000"

        logger.info("阶段 1: 开始主规则转换...");
        List<String> initialRawRules = getCurrentUfwRules();
        List<UfwRule> initialParsedRules = parseAllRules(initialRawRules);

        List<UfwRule> primaryTransformCandidates = new ArrayList<>();
        // 筛选符合阶段1转换条件的规则
        for (UfwRule rule : initialParsedRules) {
            // 跳过无效解析或已禁用的规则
            if (rule.getRuleNumber() == -1 || !rule.isEnabled()) {
                if (rule.getRuleNumber() != -1) logger.info("  跳过已禁用/解析不完整规则 #{}: {}", rule.getRuleNumber(), rule.toString());
                continue;
            }

            // 条件1: 方向为IN，动作为ALLOW, DENY, REJECT (LIMIT不在此阶段处理)
            boolean condition1_directionAndAction = "IN".equals(rule.getDirection()) &&
                    ("ALLOW".equals(rule.getAction()) || "DENY".equals(rule.getAction()) || "REJECT".equals(rule.getAction()));
            // 条件2: 原始To字段中未指定协议 (不含 "tcp", "udp")，且规则本身不是协议特定的 (例如，不是 "ssh")
            boolean condition2_protocolNotSpecifiedInRawTo = rule.getRawTo() != null &&
                    !rule.getRawTo().toLowerCase().contains("tcp") &&
                    !rule.getRawTo().toLowerCase().contains("udp") &&
                    !rule.isProtocolSpecific(); // isProtocolSpecific 确保它不是像 "ssh" 这样的服务名
            // 条件3: 清理后的To字段是一个数字端口 (或范围)
            boolean condition3_toIsNumericPort = numericPortPattern.matcher(rule.getTo()).matches();

            if (condition1_directionAndAction && condition2_protocolNotSpecifiedInRawTo && condition3_toIsNumericPort) {
                primaryTransformCandidates.add(rule);
            }
        }

        Set<String> convertedRuleKeys = new HashSet<>(); // 存储已转换规则的核心等效键

        if (primaryTransformCandidates.isEmpty()) {
            logger.info("阶段 1: 未找到需要进行主转换的规则。");
        } else {
            logger.info("阶段 1: 识别到 {} 条主转换候选规则。", primaryTransformCandidates.size());
            // 按规则编号降序排序，以便从后往前删除，避免编号变动影响
            Collections.sort(primaryTransformCandidates, Collections.reverseOrder());

            for (UfwRule candidate : primaryTransformCandidates) {
                logger.info("  主转换: 处理候选规则 #{}: {}", candidate.getRuleNumber(), candidate.toString());
                // 尝试删除原规则
                if (deleteUfwRuleByNumber(candidate.getRuleNumber())) {
                    // 记录此规则已被转换 (用于阶段2清理IPv6规则)
                    convertedRuleKeys.add(candidate.getCoreEquivalenceKey());
                    // 为TCP和UDP分别添加新规则
                    for (String protocol : Arrays.asList("tcp", "udp")) {
                        List<String> cmd = new ArrayList<>();
                        cmd.add("sudo"); cmd.add("ufw"); cmd.add(candidate.getAction().toLowerCase()); // e.g., "allow"

                        boolean isSourceAnywhere = (candidate.getFrom() == null || candidate.getFrom().equalsIgnoreCase("Anywhere"));

                        if (isSourceAnywhere) {
                            // 格式: sudo ufw allow 80/tcp
                            cmd.add(candidate.getTo() + "/" + protocol);
                        } else {
                            // 格式: sudo ufw allow proto tcp from 1.2.3.4 to any port 80
                            cmd.add("proto"); cmd.add(protocol);
                            cmd.add("from"); cmd.add(candidate.getFrom());
                            cmd.add("to"); cmd.add("any"); // 'to any' 是指定端口时的标准写法
                            cmd.add("port"); cmd.add(candidate.getTo());
                        }

                        // 如果原规则有注释，尝试添加到新规则
                        if (candidate.getComment() != null && !candidate.getComment().isEmpty()) {
                            cmd.add("comment"); cmd.add(candidate.getComment());
                        }
                        addSpecificUfwRule(cmd, protocol.toUpperCase());
                    }
                } else {
                    logger.warn("  主转换: 删除规则 #{} 失败，跳过添加新规则。", candidate.getRuleNumber());
                }
            }
        }
        logger.info("阶段 1: 主规则转换完成。收集到 {} 个已转换规则的核心键。", convertedRuleKeys.size());

        // --- 阶段 2: 全局迭代清理多余的通用 IPv6 规则 ---
        logger.info("\n阶段 2: 开始全局迭代清理多余的通用 IPv6 规则...");
        int maxCleanupIterations = 5; // 设置最大清理迭代次数，防止无限循环
        boolean changedInLastIteration;
        int iter = 0;

        for (iter = 0; iter < maxCleanupIterations; iter++) {
            logger.info("  清理迭代 #{}", iter + 1);
            changedInLastIteration = false;
            List<String> currentRawRules = getCurrentUfwRules(); // 每次迭代都重新获取规则
            List<UfwRule> currentParsedRules = parseAllRules(currentRawRules);
            List<UfwRule> ipv6GenericToDeleteThisRound = new ArrayList<>();

            // 筛选符合阶段2清理条件的IPv6规则
            for (UfwRule currentRule : currentParsedRules) {
                if (currentRule.getRuleNumber() == -1 || !currentRule.isEnabled()) continue; // 跳过无效或禁用

                // 条件1: 是IPv6规则, 方向IN, 动作是ALLOW/DENY/REJECT
                boolean c1_isRelevantIpv6 = currentRule.isIpv6() && "IN".equals(currentRule.getDirection()) &&
                        ("ALLOW".equals(currentRule.getAction()) || "DENY".equals(currentRule.getAction()) || "REJECT".equals(currentRule.getAction()));
                // 条件2: To字段未指定协议 (非 "tcp", "udp", 也非服务名如 "ssh")
                boolean c2_protocolNotSpecified = currentRule.getRawTo() != null &&
                        !currentRule.getRawTo().toLowerCase().contains("tcp") &&
                        !currentRule.getRawTo().toLowerCase().contains("udp") &&
                        !currentRule.isProtocolSpecific();
                // 条件3: To字段是数字端口
                boolean c3_toIsNumeric = numericPortPattern.matcher(currentRule.getTo()).matches();

                if (c1_isRelevantIpv6 && c2_protocolNotSpecified && c3_toIsNumeric) {
                    // 关键条件: 此IPv6规则的核心等效键在阶段1中被转换过
                    // 这意味着其对应的通用规则(通常是IPv4或IP版本无关的)已被分解为TCP/UDP特定规则
                    if (convertedRuleKeys.contains(currentRule.getCoreEquivalenceKey())) {
                        ipv6GenericToDeleteThisRound.add(currentRule);
                    }
                }
            }

            if (ipv6GenericToDeleteThisRound.isEmpty()) {
                logger.info("  本轮清理未发现多余的通用 IPv6 规则。");
                break; // 没有可清理的了，结束迭代
            }

            logger.info("  本轮清理发现 {} 条多余的通用 IPv6 规则待删除。", ipv6GenericToDeleteThisRound.size());
            Collections.sort(ipv6GenericToDeleteThisRound, Collections.reverseOrder()); // 降序删除

            for (UfwRule ruleToDelete : ipv6GenericToDeleteThisRound) {
                logger.info("    清理: 删除规则 #{}: {}", ruleToDelete.getRuleNumber(), ruleToDelete.toString());
                if (deleteUfwRuleByNumber(ruleToDelete.getRuleNumber())) {
                    changedInLastIteration = true; // 标记本轮有规则被成功删除
                }
            }

            // 如果本轮有候选规则但没有任何规则被成功删除，可能意味着存在问题或ufw状态未按预期更新
            if (!changedInLastIteration && !ipv6GenericToDeleteThisRound.isEmpty()) {
                logger.info("  本轮清理虽有候选但未成功删除任何规则，结束清理。");
                break;
            }
            if (!changedInLastIteration) { // 如果上一轮就没有变化了，就不用继续了
                break;
            }
        }
        if (iter == maxCleanupIterations) {
            logger.warn("阶段 2: 清理达到最大迭代次数 {}，可能仍有规则待处理或存在问题。", maxCleanupIterations);
        }
        logger.info("阶段 2: 全局迭代清理完成。");

        logger.info("\nUFW 规则转换和清理过程全部完成。");
        logger.info("请手动执行 'sudo ufw status numbered' 来验证更改。");
    }

    /**
     * 获取当前的UFW规则列表。
     * 执行 {@code sudo ufw status numbered} 命令并返回其输出行。
     *
     * @return 包含 {@code ufw status numbered} 输出的每一行的列表。
     * @throws IOException 如果执行命令或读取输出时发生I/O错误。
     * @throws InterruptedException 如果等待命令完成时线程被中断。
     * @throws TimeoutException 如果命令执行超时。
     */
    private static List<String> getCurrentUfwRules() throws IOException, InterruptedException, TimeoutException {
        ProcessResult result = new ProcessExecutor()
                .command("sudo", "ufw", "status", "numbered")
                .readOutput(true).timeout(10, TimeUnit.SECONDS).execute();
        if (result.getExitValue() != 0) {
            logger.error("辅助: 获取UFW状态失败. Code: {}, Output: {}", result.getExitValue(), result.outputUTF8());
            throw new IOException("获取UFW状态失败，退出码: " + result.getExitValue() + ", 输出: " + result.outputUTF8());
        }
        return Arrays.asList(result.outputUTF8().split("\\r?\\n"));
    }

    /**
     * 将原始的UFW规则行列表解析为 {@link UfwRule} 对象列表。
     *
     * @param rawLines 从 {@link #getCurrentUfwRules()} 获取的原始规则行字符串列表。
     * @return 解析后的 {@link UfwRule} 对象列表。无法解析的行将被忽略。
     */
    private static List<UfwRule> parseAllRules(List<String> rawLines) {
        List<UfwRule> rules = new ArrayList<>();
        for (String line : rawLines) {
            UfwRule rule = UfwRule.parseFromStatus(line);
            if (rule != null) {
                rules.add(rule);
            }
        }
        return rules;
    }

    /**
     * 根据规则编号删除一条UFW规则。
     * 执行 {@code sudo ufw --force delete <ruleNum>} 命令。
     * {@code --force} 选项用于避免交互式确认。
     *
     * @param ruleNum 要删除的规则的编号。
     * @return 如果删除成功（命令退出码为0），返回 {@code true}；否则返回 {@code false}。
     */
    private static boolean deleteUfwRuleByNumber(int ruleNum) {
        try {
            ProcessResult result = new ProcessExecutor()
                    .command("sudo", "ufw", "--force", "delete", String.valueOf(ruleNum))
                    .readOutput(true).timeout(5, TimeUnit.SECONDS).execute();
            if (result.getExitValue() == 0) {
                logger.info("  辅助: 成功删除规则 #{}. UFW输出: {}", ruleNum, result.outputUTF8().trim());
                return true;
            } else {
                logger.error("  辅助: 删除规则 #{} 失败. Code: {}, UFW输出: {}", ruleNum, result.getExitValue(), result.outputUTF8().trim());
                return false;
            }
        } catch (IOException | InterruptedException | TimeoutException e) { //捕获更具体的异常
            logger.error("  辅助: 删除规则 #{} 时发生异常.", ruleNum, e);
            return false;
        }
    }

    /**
     * 添加一条指定的UFW规则。
     * 命令参数由 {@code commandList} 提供，通常以 {@code sudo ufw <action> ...} 开始。
     *
     * @param commandList 包含完整UFW命令及其参数的列表 (例如, ["sudo", "ufw", "allow", "80/tcp"])。
     * @param protocolForLog 用于日志记录的协议名称 (例如 "TCP", "UDP")，仅为日志提供上下文。
     * @return 如果添加成功（命令退出码为0），返回 {@code true}；否则返回 {@code false}。
     */
    private static boolean addSpecificUfwRule(List<String> commandList, String protocolForLog) {
        try {
            // 从命令列表中提取实际的 ufw 命令部分用于日志记录 (不包括 "sudo ufw")
            String cmdStrForLog = String.join(" ", commandList.subList(2, commandList.size()));
            ProcessResult result = new ProcessExecutor().command(commandList)
                    .readOutput(true).timeout(5, TimeUnit.SECONDS).execute();

            if (result.getExitValue() == 0) {
                logger.info("  辅助: 成功添加 {} 规则 ({}). UFW输出: {}", protocolForLog, cmdStrForLog, result.outputUTF8().trim());
                return true;
            } else {
                logger.error("  辅助: 添加 {} 规则 ({}) 失败. Code: {}, UFW输出: {}", protocolForLog, cmdStrForLog, result.getExitValue(), result.outputUTF8().trim());
                return false;
            }
        } catch (IOException | InterruptedException | TimeoutException e) { //捕获更具体的异常
            logger.error("  辅助: 添加 {} 规则时发生异常.", protocolForLog, e);
            return false;
        }
    }

    /**
     * 主入口点，用于测试UFW规则转换工具。
     * @param args 命令行参数 (当前未使用)。
     */
    public static void main(String[] args) {
        logger.info("启动 UFW 规则转换工具 (使用自定义 UfwRule 解析器)...");
        try {
            //sudo ufw reset
            //sudo ufw enable # 如果 reset 后禁用了 ufw
            //
            //sudo ufw status numbered
            //
            //
            //# --- 阶段1应转换的规则 ---
            //# 1. 通用数字端口规则 (IPv4/Any)
            //sudo ufw allow 80 comment "Generic HTTP port"
            //sudo ufw allow 443 comment "Generic HTTPS port"
            //sudo ufw deny 10000 comment "Generic deny on 10000"
            //
            //# 2. 通用数字端口规则，带特定源 (IPv4/Any)
            //sudo ufw allow from 192.168.1.100 to any port 2222 comment "Generic from specific IP"
            //
            //# --- 阶段2应清理的通用IPv6规则 ---
            //# ufw 在添加上述通用规则时，如果IPV6=yes，通常会自动创建对应的 (v6) 规则。
            //# 如果没有自动创建，你可以手动添加来确保测试覆盖：
            //# sudo ufw allow 80/tcp # 会创建v4和v6
            //# sudo ufw allow 80/udp # 会创建v4和v6
            //# 所以，我们主要依赖 ufw 自动创建。如果脚本运行后发现通用 (v6) 规则还在，
            //# 说明 ufw 没有自动创建它们，或者脚本的阶段1没有正确转换其v4对应版本。
            //# 为了确保测试，我们可以观察 `ufw status numbered` 在添加上面规则后的情况。
            //# 如果缺少 `(v6)` 的通用规则，可以手动添加以测试阶段2，例如：
            //# sudo ufw route allow 80 proto ipv6 comment "Manually added generic IPv6 for port 80 to test cleanup"
            //# 注意：上述 `route allow` 只是一个例子，更直接的是看 `ufw status numbered` 是否有 `80 (v6)` 这样的行。
            //# 通常 `sudo ufw allow 80` 就会产生 v4 和 v6 的通用版本。
            //
            //# --- 不应被转换的规则 ---
            //# 3. 已明确协议的规则
            //sudo ufw allow 22/tcp comment "SSH TCP specific"
            //sudo ufw allow 53/udp comment "DNS UDP specific"
            //
            //# 4. 使用服务名的规则
            //sudo ufw allow 'Apache Full' comment "Apache Full service" # 服务名可能包含空格，用引号包围
            //sudo ufw allow OpenSSH comment "OpenSSH service (no spaces)"
            //
            //# 5. LIMIT 规则 (脚本当前逻辑不转换这些，但会解析)
            //sudo ufw limit ssh/tcp comment "Limit SSH TCP"
            //sudo ufw limit 3389 comment "Limit RDP generic" # 这个可能会被意外转换，如果解析器把 LIMIT 算作 Action
            //
            //# 6. OUT 方向规则
            //sudo ufw allow out 587 comment "Allow SMTP out generic"
            //
            //# 7. 已有明确协议的IPv6规则 (不应被清理)
            //sudo ufw allow from 2001:db8:abcd:0012::1 to any port 22 proto tcp comment "Allow SSH from specific IPv6 host"
            //
            //sudo ufw allow from 2001:db8:acad:1::/64 to any port 80 proto tcp comment "Allow HTTP from IPv6 subnet"
            //sudo ufw allow from 2001:db8:acad:1::/64 to any port 443 proto tcp comment "Allow HTTPS from IPv6 subnet"
            //
            //sudo ufw deny from 2001:db8:dead:beef::bad to any comment "Block all traffic from malicious IPv6 host"
            //
            //sudo ufw allow from 2001:db8:office::/56 to 2001:db8:server::100 port 5353 proto udp comment "Allow mDNS from office IPv6 to specific server IPv6 IP"
            //
            //# 8. 禁用规则
            //sudo ufw deny 9999 comment "This rule will be disabled"
            //# 获取上面规则的编号 (假设是 N)，然后禁用它：
            //# sudo ufw status numbered  (查看 9999 的编号)
            //# sudo ufw delete <N> (如果想完全移除再添加为禁用)
            //# 或者，如果ufw支持直接添加禁用规则 (通常不支持，一般是先添加再禁用)
            //# 更好的方式是先添加，然后用脚本之外的方式将其输出修改为 "[ N] ... [disabled]" 来模拟
            //# 一个简单的方法是，先添加，运行脚本一次，然后手动编辑 `ufw status numbered` 的模拟输出来测试 `[disabled]` 的解析
            //
            //# 为了测试禁用，我们可以先添加一个规则，然后找到它的编号并删除，再手动模拟一个禁用的行。
            //# 或者，如果你的 `ufw` 版本支持通过 `insert` 带 `disabled` 关键字（不常见）。
            //# 最简单的是，先添加它，然后运行你的Java程序前，手动修改 `getCurrentUfwRules` 的返回内容，
            //# 伪造一条包含 `[disabled]` 的规则行。
            //
            //# 9. 规则号码较大的情况 (测试排序和删除)
            //sudo ufw allow 50000
            //sudo ufw allow 50001
            //
            //# --- 用于模拟解析器特殊情况的规则 (如果需要) ---
            //# 例如，测试Action和Direction合并的情况 (ALLOWIN)
            //# `ufw` 命令本身通常不会直接生成 `ALLOWIN` 这样的输出，解析器主要是为了兼容可能的 `ufw status` 变体。
            //# 可以通过手动修改 `getCurrentUfwRules` 返回的字符串来测试这种解析。
            covertUfwRuleToDetailStyle();
        } catch (IOException | InterruptedException | TimeoutException e) {
            logger.error("UFW 规则转换工具顶层执行失败。", e);
        }
        logger.info("UFW 规则转换工具运行结束。");
    }
}