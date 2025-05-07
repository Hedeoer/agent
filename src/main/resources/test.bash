sudo ufw reset
sudo ufw enable # 如果 reset 后禁用了 ufw

sudo ufw status numbered


# --- 阶段1应转换的规则 ---
# 1. 通用数字端口规则 (IPv4/Any)
sudo ufw allow 80 comment "Generic HTTP port"
sudo ufw allow 443 comment "Generic HTTPS port"
sudo ufw deny 10000 comment "Generic deny on 10000"

# 2. 通用数字端口规则，带特定源 (IPv4/Any)
sudo ufw allow from 192.168.1.100 to any port 2222 comment "Generic from specific IP"

# --- 阶段2应清理的通用IPv6规则 ---
# ufw 在添加上述通用规则时，如果IPV6=yes，通常会自动创建对应的 (v6) 规则。
# 如果没有自动创建，你可以手动添加来确保测试覆盖：
# sudo ufw allow 80/tcp # 会创建v4和v6
# sudo ufw allow 80/udp # 会创建v4和v6
# 所以，我们主要依赖 ufw 自动创建。如果脚本运行后发现通用 (v6) 规则还在，
# 说明 ufw 没有自动创建它们，或者脚本的阶段1没有正确转换其v4对应版本。
# 为了确保测试，我们可以观察 `ufw status numbered` 在添加上面规则后的情况。
# 如果缺少 `(v6)` 的通用规则，可以手动添加以测试阶段2，例如：
# sudo ufw route allow 80 proto ipv6 comment "Manually added generic IPv6 for port 80 to test cleanup"
# 注意：上述 `route allow` 只是一个例子，更直接的是看 `ufw status numbered` 是否有 `80 (v6)` 这样的行。
# 通常 `sudo ufw allow 80` 就会产生 v4 和 v6 的通用版本。

# --- 不应被转换的规则 ---
# 3. 已明确协议的规则
sudo ufw allow 22/tcp comment "SSH TCP specific"
sudo ufw allow 53/udp comment "DNS UDP specific"

# 4. 使用服务名的规则
sudo ufw allow 'Apache Full' comment "Apache Full service" # 服务名可能包含空格，用引号包围
sudo ufw allow OpenSSH comment "OpenSSH service (no spaces)"

# 5. LIMIT 规则 (脚本当前逻辑不转换这些，但会解析)
sudo ufw limit ssh/tcp comment "Limit SSH TCP"
sudo ufw limit 3389 comment "Limit RDP generic" # 这个可能会被意外转换，如果解析器把 LIMIT 算作 Action

# 6. OUT 方向规则
sudo ufw allow out 587 comment "Allow SMTP out generic"

# 7. 已有明确协议的IPv6规则 (不应被清理)
sudo ufw allow from 2001:db8:abcd:0012::1 to any port 22 proto tcp comment "Allow SSH from specific IPv6 host"

sudo ufw allow from 2001:db8:acad:1::/64 to any port 80 proto tcp comment "Allow HTTP from IPv6 subnet"
sudo ufw allow from 2001:db8:acad:1::/64 to any port 443 proto tcp comment "Allow HTTPS from IPv6 subnet"

sudo ufw deny from 2001:db8:dead:beef::bad to any comment "Block all traffic from malicious IPv6 host"

sudo ufw allow from 2001:db8:office::/56 to 2001:db8:server::100 port 5353 proto udp comment "Allow mDNS from office IPv6 to specific server IPv6 IP"

# 8. 禁用规则
sudo ufw deny 9999 comment "This rule will be disabled"
# 获取上面规则的编号 (假设是 N)，然后禁用它：
# sudo ufw status numbered  (查看 9999 的编号)
# sudo ufw delete <N> (如果想完全移除再添加为禁用)
# 或者，如果ufw支持直接添加禁用规则 (通常不支持，一般是先添加再禁用)
# 更好的方式是先添加，然后用脚本之外的方式将其输出修改为 "[ N] ... [disabled]" 来模拟
# 一个简单的方法是，先添加，运行脚本一次，然后手动编辑 `ufw status numbered` 的模拟输出来测试 `[disabled]` 的解析

# 为了测试禁用，我们可以先添加一个规则，然后找到它的编号并删除，再手动模拟一个禁用的行。
# 或者，如果你的 `ufw` 版本支持通过 `insert` 带 `disabled` 关键字（不常见）。
# 最简单的是，先添加它，然后运行你的Java程序前，手动修改 `getCurrentUfwRules` 的返回内容，
# 伪造一条包含 `[disabled]` 的规则行。

# 9. 规则号码较大的情况 (测试排序和删除)
sudo ufw allow 50000
sudo ufw allow 50001

# --- 用于模拟解析器特殊情况的规则 (如果需要) ---
# 例如，测试Action和Direction合并的情况 (ALLOWIN)
# `ufw` 命令本身通常不会直接生成 `ALLOWIN` 这样的输出，解析器主要是为了兼容可能的 `ufw status` 变体。
# 可以通过手动修改 `getCurrentUfwRules` 返回的字符串来测试这种解析。