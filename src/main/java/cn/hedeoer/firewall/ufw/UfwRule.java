package cn.hedeoer.firewall.ufw;


import cn.hedeoer.util.IpUtils;

import java.util.Locale;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * UFW 防火墙规则对象
 * 表示一条从 'ufw status numbered' 命令输出中解析得到的防火墙规则。
 * 包含规则编号、目标、动作、方向、来源、注释、IPv6状态和启用状态(通过检查 [disabled] 标记)。
 */
public class UfwRule {
    /**
     * 规则编号。
     * <p>
     * 可能的值:
     * <ul>
     *   <li><b>-1</b>: (默认值) 表示规则没有编号，或者编号解析失败。通常用于非编号规则或解析错误。
     *   <li><b>正整数 (e.g., 1, 2, 3, ...)</b>: 从 'ufw status numbered' 输出中解析得到的规则的实际编号。
     * </ul>
     * 含义: 用于唯一标识和管理（如删除）规则。
     */
    private int ruleNumber = -1;

    /**
     * 规则的目标 (To)。
     * <p>
     * 可能的值 (字符串):
     * <ul>
     *   <li><b>"Anywhere"</b>: (或其等价的解析后表示，如 "any") 表示匹配任何目标IP地址或端口（取决于规则类型）。通常在 'ufw status' 中出现。
     *   <li><b>端口号 (e.g., "80", "22")</b>: 表示目标 TCP 或 UDP 端口号。
     *   <li><b>端口号/协议 (e.g., "80/tcp", "53/udp")</b>: 表示特定协议的目标端口号。
     *   <li><b>服务名称 (e.g., "ssh", "http")</b>: 表示在 /etc/services 中定义的服务名称，对应特定的端口和协议。
     *   <li><b>端口范围 (e.g., "60000:61000/tcp")</b>: 表示一个目标端口范围。
     *   <li><b>IP 地址 (e.g., "192.168.1.100")</b>: 在路由规则 (FORWARD chain) 中，表示目标网络或主机的 IP 地址。
     *   <li><b>IP 地址/子网掩码 (e.g., "10.0.0.0/8")</b>: 在路由规则中，表示目标网络。
     *   <li><b>IPv6 地址 (e.g., "2001:db8::1")</b>: 类似于 IPv4 地址，用于 IPv6 路由规则。
     *   <li><b>IPv6 地址/前缀长度 (e.g., "2001:db8::/32")</b>: 类似于 IPv4 CIDR，用于 IPv6 路由规则。
     *   <li><b>可能为 null 或空字符串</b>: 如果解析失败或规则不完整，尽管解析器会尝试设置为 "Anywhere"。
     * </ul>
     * 含义: 定义了数据包要匹配的目标。对于 INPUT/OUTPUT 链，通常是端口或服务；对于 FORWARD 链，通常是目标 IP 地址或网络。
     */
    private String to;

    /**
     * 规则的动作 (Action)。
     * <p>
     * 可能的值 (字符串, 通常解析后为大写):
     * <ul>
     *   <li><b>"ALLOW"</b>: 允许匹配的数据包通过。
     *   <li><b>"DENY"</b>: 拒绝匹配的数据包，并且**静默丢弃** (DROP)，不向发送方发送任何响应。
     *   <li><b>"REJECT"</b>: 拒绝匹配的数据包，并且会向发送方发送一个错误消息 (如 TCP RST 或 ICMP port unreachable)。
     *   <li><b>"LIMIT"</b>: 限制连接速率。如果来自同一 IP 的连接尝试在短时间内超过一定次数，则拒绝连接。通常隐式地允许初始连接，然后根据速率限制。
     *   <li><b>"LOG"</b>: （此字段通常不直接存储 "LOG"，而是通过规则中的 `log` 或 `log-all` 关键字指示日志记录行为。Action 仍然是 ALLOW/DENY/REJECT/LIMIT 之一）。
     *         然而，如果 ufw 内部或某些解析方式将纯日志规则视为一种特殊动作，可能会有此值。更常见的是，日志是规则的一个属性。
     *   <li><b>可能为 null 或空字符串</b>: 如果解析失败。解析器会尝试确保此字段不为空。
     * </ul>
     * 含义: 定义了当数据包匹配此规则时防火墙应执行的操作。
     */
    private String action;

    /**
     * 规则的方向 (Direction)。
     * <p>
     * 可能的值 (字符串, 通常解析后为大写):
     * <ul>
     *   <li><b>"IN"</b>: 表示入站流量 (数据包进入防火墙所在的主机)。
     *   <li><b>"OUT"</b>: 表示出站流量 (数据包从防火墙所在的主机发出)。
     *   <li><b>null</b>: (默认或解析后) 如果方向没有在规则中明确指定，并且无法从动作（如 "LIMIT" 默认为 "IN"）或上下文推断出来。
     *                对于 `ufw allow <port>` 这样的简单规则，'ufw status' 输出可能不会显式展示 'IN'，但它通常是隐含的。
     *                解析器可能根据上下文将其设置为 "IN"。
     * </ul>
     * 含义: 指定规则适用于入站还是出站流量。
     */
    private String direction;

    /**
     * 规则的来源 (From)。
     * <p>
     * 可能的值 (字符串):
     * <ul>
     *   <li><b>"Anywhere"</b>: (或其等价的解析后表示，如 "any") 表示匹配来自任何源 IP 地址的流量。
     *   <li><b>IP 地址 (e.g., "192.168.1.100", "2001:db8::1")</b>: 表示流量必须来自此特定 IP 地址。
     *   <li><b>IP 地址/子网掩码或前缀长度 (e.g., "192.168.0.0/16", "2001:db8::/32")</b>: 表示流量必须来自此特定网络。
     *   <li><b>可能为 null 或空字符串</b>: 如果解析失败，尽管解析器会尝试设置为 "Anywhere"。
     * </ul>
     * 含义: 定义了数据包要匹配的来源。
     */
    private String from;

    /**
     * 规则的注释 (Comment)。
     * <p>
     * 可能的值 (字符串):
     * <ul>
     *   <li><b>任何用户定义的字符串 (e.g., "# Allow SSH", "Block malicious IP")</b>: 用户在添加规则时提供的描述性文本。
     *   <li><b>null</b>: 如果规则没有注释。
     *   <li><b>空字符串 ""</b>: 如果注释被显式设置为空。
     * </ul>
     * 含义: 为规则提供人类可读的上下文或解释。
     */
    private String comment;

    /**
     * 标记规则是否为 IPv6 规则。
     * <p>
     * 可能的值:
     * <ul>
     *   <li><b>true</b>: 此规则适用于 IPv6 流量。
     *         这可能是因为规则行中明确包含 "(v6)" 标记，或者 "From" / "To" 字段包含有效的 IPv6 地址。
     *   <li><b>false</b>: (默认值或解析后确定) 此规则适用于 IPv4 流量，或者不特定于 IPv6。
     * </ul>
     * 含义: 区分规则是应用于 IPv4 协议栈还是 IPv6 协议栈。
     * 注意: 有些 UFW 规则（如 `ufw allow 22`）默认同时应用于 IPv4 和 IPv6 (如果 IPv6 已启用)。
     * 这种情况下，`ufw status numbered` 可能会为 IPv4 和 IPv6 各显示一条规则。此字段帮助区分解析到的是哪条。
     */
    private boolean isIpv6;

    /**
     * 标记规则是否已启用。
     * <p>
     * 可能的值:
     * <ul>
     *   <li><b>true</b>: (默认值或解析后确定) 规则当前是活动的，防火墙会根据此规则处理流量。
     *   <li><b>false</b>: 规则已被禁用。这通常通过在 'ufw status numbered' 输出中规则行末尾的 "[disabled]" 标记来识别。
     *          禁用的规则存在于配置中，但当前不生效。
     * </ul>
     * 含义: 表示规则的当前激活状态。
     */
    private boolean enabled;

    private static final Pattern NUMBERED_RULE_PATTERN = Pattern.compile("^\\[\\s*(\\d+)\\]\\s*(.*)");

    // 核心正则表达式，调整为捕获末尾的注释（第5组）
    // 捕获组:
    // 1: To
    // 2: Action (可能是 Action+Direction)
    // 3: Direction (可选, 如果 Action 和 Direction 分开)
    // 4: From
    // 5: Comment (可选, From之后用至少两个空格隔开的剩余部分)
    private static final Pattern CORE_RULE_PATTERN_WITH_COMMENT =
            Pattern.compile("^(\\S+)\\s{2,}(\\S+)(?:\\s+(\\S+))?\\s{2,}(\\S+)(?:\\s{2,}(.*))?$");

    // 备用三列结构，调整为捕获末尾的注释（第4组）
    // 捕获组:
    // 1: To
    // 2: Action (可能是 Action+Direction)
    // 3: From
    // 4: Comment (可选, From之后用至少两个空格隔开的剩余部分)
    private static final Pattern THREE_COLUMN_PATTERN_WITH_COMMENT =
            Pattern.compile("^(\\S+)\\s{2,}(\\S+)\\s{2,}(\\S+)(?:\\s{2,}(.*))?$");

    // 检查端口格式，用于辅助判断 "To" 字段是否为 IP
    private static final Pattern NUMERIC_PORT_PATTERN = Pattern.compile("^\\d+(:\\d+)?(/\\w+)?$");


    public UfwRule() {
    }

    public static UfwRule parseFromStatus(String rawLine) {
        if (rawLine == null || rawLine.trim().isEmpty() ||
                rawLine.contains("--") ||
                (rawLine.contains("To") && rawLine.contains("Action") && rawLine.contains("From"))) {
            return null; // 忽略表头或无效行
        }

        UfwRule rule = new UfwRule();
        String lineToParse = rawLine.trim();
        String originalLineForComment = lineToParse; // 保留原始行（去除编号后）用于后续注释提取

        // 1. 解析并移除规则编号
        Matcher numberedMatcher = NUMBERED_RULE_PATTERN.matcher(lineToParse);
        if (numberedMatcher.find()) {
            try {
                rule.ruleNumber = Integer.parseInt(numberedMatcher.group(1));
            } catch (NumberFormatException e) {
                System.err.println("警告: 无法从行中解析规则编号: " + rawLine);
                rule.ruleNumber = -1; // 保持默认
            }
            lineToParse = numberedMatcher.group(2).trim();
            originalLineForComment = lineToParse; // 更新用于注释提取的行
        } else {
            rule.ruleNumber = -1; // 无编号
        }

        // 2. 检查规则是否被禁用 (在分离注释和核心规则之前处理，因为它通常在行尾)
        if (lineToParse.toLowerCase(Locale.ROOT).contains("[disabled]")) {
            rule.enabled = false;
            lineToParse = lineToParse.replaceAll("(?i)\\[disabled\\]", "").trim();
            originalLineForComment = lineToParse; // 更新
        } else {
            rule.enabled = true;
        }

        // === 注释提取逻辑调整 ===
        String rulePartForCoreParsing; // 用于核心字段解析的字符串
        String potentialTrailingComment = null; // 可能的尾随注释

        // 3. 优先尝试分离以 '#' 开头的注释 (保留#)
        int hashCommentStartIndex = -1;
        boolean inQuotes = false;
        for (int i = 0; i < lineToParse.length(); i++) {
            char c = lineToParse.charAt(i);
            if (c == '"' || c == '\'') {
                inQuotes = !inQuotes;
            } else if (c == '#' && !inQuotes) {
                hashCommentStartIndex = i;
                break;
            }
        }

        if (hashCommentStartIndex != -1) {
            // 如果找到 '#' 注释，则 rulePart 是 '#' 之前的内容
            rulePartForCoreParsing = lineToParse.substring(0, hashCommentStartIndex).trim();
            // 注释是 '#' 及其之后的内容 (保留 '#')
            rule.comment = lineToParse.substring(hashCommentStartIndex).trim();
        } else {
            // 如果没有 '#' 注释，则整行（目前处理过的）都用于核心解析
            rulePartForCoreParsing = lineToParse;
            rule.comment = null; // 先置为null，后续可能被尾随注释覆盖
        }

        // 4. 预处理 rulePartForCoreParsing: 移除 (out), (in), (v6) 等标记
        boolean rulePartHadGlobalV6Marker = rulePartForCoreParsing.contains("(v6)");
        rulePartForCoreParsing = rulePartForCoreParsing.replaceAll("\\s*\\((out|in)\\)\\s*$", "").trim();
        rulePartForCoreParsing = rulePartForCoreParsing.replaceAll("\\s*\\(\\s*(?:ইন| ইন)\\s*\\)\\s*$", "").trim();
        String cleanedRulePart = rulePartForCoreParsing.replaceAll("\\(v6\\)", "").trim();


        // 5. 解析核心规则字段 (To, Action, Direction, From)
        // 并尝试从这里提取尾随注释 (如果之前没有找到 '#' 注释)
        boolean parsedSuccessfully = false;
        String coreFieldsMatchedString = null; // 记录核心字段匹配到的字符串部分

        Matcher coreMatcher = CORE_RULE_PATTERN_WITH_COMMENT.matcher(cleanedRulePart);
        if (coreMatcher.matches()) { // 使用 matches() 确保整个 cleanedRulePart 被消费
            rule.to = coreMatcher.group(1).trim();
            String actionOrActionDirection = coreMatcher.group(2).trim();
            String explicitDirection = coreMatcher.group(3); // 可选的第三个动作/方向组
            rule.from = coreMatcher.group(4).trim();
            potentialTrailingComment = coreMatcher.group(5); // 获取可能的尾随注释

            if (explicitDirection != null && !explicitDirection.trim().isEmpty()) {
                rule.action = actionOrActionDirection;
                rule.direction = explicitDirection.trim();
            } else {
                parseActionDirection(rule, actionOrActionDirection);
            }
            parsedSuccessfully = true;
            // 估算核心字段占用的原始 cleanedRulePart 的长度
            // 注意：这里是一个近似，因为\s{2,}的匹配长度不定
            // 更精确的方式是记录 matcher.end(4) 即 From 字段的结束位置
            // 然后从 cleanedRulePart.substring(matcher.end(4)) 获取尾部
            // 但由于正则本身已捕获第5组作为注释，我们可以直接用它
        } else {
            Matcher threeColMatcher = THREE_COLUMN_PATTERN_WITH_COMMENT.matcher(cleanedRulePart);
            if (threeColMatcher.matches()) {
                rule.to = threeColMatcher.group(1).trim();
                parseActionDirection(rule, threeColMatcher.group(2).trim());
                rule.from = threeColMatcher.group(3).trim();
                potentialTrailingComment = threeColMatcher.group(4);
                parsedSuccessfully = true;
            } else {
                // 作为最后的尝试，按多个空格分割
                // 这种方式提取尾随注释会比较困难，除非固定列数
                // 这里简化，如果用 split，则假定注释已被 '#' 处理或不适用此方法提取
                String[] columns = splitByMultipleSpaces(cleanedRulePart);
                if (columns.length >= 3) { // 至少 To Action From
                    rule.to = columns[0];
                    String actionCandidate = columns[1];

                    if (columns.length >= 4) { // To Action Direction From [Comment...]
                        rule.action = actionCandidate;
                        rule.direction = columns[2];
                        rule.from = columns[3];
                        if (columns.length > 4 && rule.comment == null) { // 如果有第5列且无#注释
                            StringBuilder sb = new StringBuilder();
                            for(int i=4; i<columns.length; i++){
                                sb.append(columns[i]).append(" ");
                            }
                            potentialTrailingComment = sb.toString().trim();
                        }
                    } else { // To Action From [Comment...]
                        rule.from = columns[2];
                        parseActionDirection(rule, actionCandidate);
                        // 如果用 split 且只有3列，但原始行比这3列长，则可能是尾随注释
                        // 这个逻辑比较复杂，暂时依赖正则的捕获组
                    }
                    parsedSuccessfully = true;
                }
            }
        }

        if (!parsedSuccessfully) {
            System.err.println("无法解析UFW规则核心字段: " + rawLine + " (处理后规则部分: " + cleanedRulePart + ")");
            return null; // 如果核心字段都无法解析，则认为规则无效
        }

        // 如果没有通过 '#' 找到注释，并且正则捕获到了尾随文本，则使用它
        if (rule.comment == null && potentialTrailingComment != null && !potentialTrailingComment.trim().isEmpty()) {
            rule.comment = potentialTrailingComment.trim();
        }


        // 6. 标准化 action 和 direction
        if (rule.action != null) rule.action = rule.action.toUpperCase(Locale.ROOT);
        if (rule.direction != null) {
            rule.direction = rule.direction.toUpperCase(Locale.ROOT);
        }
        // 如果 direction 仍为 null，根据 action 设置默认值
        if (rule.direction == null) {
            if ("LIMIT".equals(rule.action) || "ALLOW".equals(rule.action) ||
                    "DENY".equals(rule.action) || "REJECT".equals(rule.action)) {
                rule.direction = "IN"; // 这些动作如果无明确方向，通常是 IN
            }
        }


        // 7. 确定是否为 IPv6 规则
        // (v6) 标记的检查应该基于分离注释之前的 rulePartForCoreParsing 或更早的 lineToParse
        // 因为 (v6) 可能出现在注释 '#' 之后或尾随注释中
        // 我们用 originalLineForComment（在移除编号和[disabled]之后，但在分离#注释和核心字段之前）
        // 或者，更简单的是，如果 rulePartHadGlobalV6Marker 是从分离了#注释的 rulePartForCoreParsing 来的，
        // 那么如果(v6)在#后，它不会被检测到。
        // 改为在原始行（去除编号和disabled后）检查 (v6) 标记
        boolean lineHadGlobalV6Marker = originalLineForComment.contains("(v6)");
        rule.isIpv6 = lineHadGlobalV6Marker;

        if (!rule.isIpv6) {
            if (rule.from != null && !isSpecialAddress(rule.from) && IpUtils.isIpv6(stripCidr(rule.from))) {
                rule.isIpv6 = true;
            }
        }
        if (!rule.isIpv6) {
            if (rule.to != null && !isSpecialAddress(rule.to) && !NUMERIC_PORT_PATTERN.matcher(stripCidr(rule.to)).matches() && IpUtils.isIpv6(stripCidr(rule.to))) {
                rule.isIpv6 = true;
            }
        }

        // 确保关键字段不为 null 或根据 ufw 默认行为填充
        if (rule.action == null || rule.action.isEmpty()) {
            System.err.println("解析错误: Action 字段为空。原始行: " + rawLine);
            return null; // Action 是必须的
        }

        if (rule.from == null || rule.from.isEmpty()) {
            rule.from = "Anywhere";
        }
        if (rule.to == null || rule.to.isEmpty()) {
            rule.to = "Anywhere";
        }

        return rule;
    }

    private static void parseActionDirection(UfwRule rule, String actionCandidate) {
        actionCandidate = actionCandidate.trim().toUpperCase(Locale.ROOT);

        if (actionCandidate.endsWith("IN") && actionCandidate.length() > 2 && !actionCandidate.equals("IN")) {
            String potentialAction = actionCandidate.substring(0, actionCandidate.length() - 2);
            if (isKnownUfwAction(potentialAction)) {
                rule.action = potentialAction;
                rule.direction = "IN";
                return;
            }
        }
        if (actionCandidate.endsWith("OUT") && actionCandidate.length() > 3 && !actionCandidate.equals("OUT")) {
            String potentialAction = actionCandidate.substring(0, actionCandidate.length() - 3);
            if (isKnownUfwAction(potentialAction)) {
                rule.action = potentialAction;
                rule.direction = "OUT";
                return;
            }
        }
        rule.action = actionCandidate; // 如果不符合上述，整个是 Action
        // direction 保持 null，后续逻辑会根据 action 或上下文设置
    }

    private static boolean isKnownUfwAction(String action) {
        if (action == null) return false;
        String upperAction = action.toUpperCase(Locale.ROOT);
        return upperAction.equals("ALLOW") || upperAction.equals("DENY") ||
                upperAction.equals("REJECT") || upperAction.equals("LIMIT");
    }

    private static String[] splitByMultipleSpaces(String line) {
        if (line == null) return new String[0];
        // 使用正向前查和负向前查来避免分割引号内的空格（简化版，可能不完美）
        // String[] parts = line.trim().split("\\s+(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)(?=(?:[^']*'[^']*')*[^']*$)");
        // 为简单起见，暂时还用原来的 split，假设注释中不含复杂引号和多个空格分隔的列
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


    // Getters and Setters
    public int getRuleNumber() { return ruleNumber; }
    public void setRuleNumber(int ruleNumber) { this.ruleNumber = ruleNumber; }
    public String getTo() { return to; }
    public void setTo(String to) { this.to = to; }
    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }
    public String getDirection() { return direction; }
    public void setDirection(String direction) { this.direction = direction; }
    public String getFrom() { return from; }
    public void setFrom(String from) { this.from = from; }
    public String getComment() { return comment; }
    public void setComment(String comment) { this.comment = comment; }
    public boolean isIpv6() { return isIpv6; }
    public void setIpv6(boolean ipv6) { isIpv6 = ipv6; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    @Override
    public String toString() { // 修改 toString 以更好地反映规则和注释
        StringBuilder sb = new StringBuilder();
        if (ruleNumber != -1) {
            sb.append("[").append(ruleNumber).append("] ");
        }
        sb.append(to != null ? to : "null_to");
        sb.append("  ").append(action != null ? action : "null_action");
        if (direction != null) {
            sb.append(" ").append(direction);
        }
        sb.append("  ").append(from != null ? from : "null_from");

        // isIpv6 和 enabled 标记应该在核心规则部分之后，注释之前
        // 但 ufw status 输出格式是 (v6) 散布在 To 和 From 中
        // 如果 isIpv6 是通过解析 (v6) 得到的，那么原始的 (v6) 已经被 cleanedRulePart 移除了
        // 我们需要在 toString 中根据 isIpv6 字段决定是否添加一个通用的 (v6) 提示，
        // 或者更忠实地反映原始行的 (v6) 位置（但这更复杂）
        // 这里简单地在核心规则后，注释前添加 (v6) 提示（如果 isIpv6 为 true）
        // 并且是在清理了原始 (v6) 标记之后，所以这里添加的是一个总的标记
        // （这可能与原始行中 (v6) 的确切位置不完全一致，但表达了规则的IPv6属性）

        // 注意：ufw status 通常将 (v6) 放在 To 和/或 From 字段中，或者作为全局提示
        // 这里的 toString 只是为了调试，可能无法完美复现原始行的 (v6) 布局
        if (isIpv6 && !to.contains("(v6)") && !from.contains("(v6)")) { // 如果核心字段没带(v6)但规则是v6
            //sb.append(" (v6)"); // 决定是否在这里加，或依赖原始字段本身包含它
        }

        if (!enabled) {
            sb.append(" [disabled]");
        }
        if (comment != null && !comment.isEmpty()) {
            // 如果注释本身不是以 # 开头，并且我们想保持 ufw status 的风格，可以手动加
            // 但根据需求，如果原始注释有 # 就保留，没有就不加
            sb.append("  ").append(comment);
        }
        return sb.toString().trim(); // 去掉末尾可能的多余空格
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