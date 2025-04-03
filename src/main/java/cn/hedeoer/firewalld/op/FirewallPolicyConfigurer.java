package cn.hedeoer.firewalld.op;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zeroturnaround.exec.ProcessExecutor;
import org.zeroturnaround.exec.ProcessResult;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * 使用前置条件：
 * <p>1. 用户拥有sudo权限才能完成配置</p>
 * <p>2. 并且用户拥有免密sudo权限</p>
 *
 *
 * 使用zt-exec 创建 polkit 规则文件来获取使用dbus api操作firewalld的权限
 * <p>1. 检查用户（当前系统用户）是否已经拥有防火墙操作授权</p>
 * <p>2. 对用户授权</p>
 * <ul>
 *     <li>2.1 创建 /etc/polkit-1/rules.d/90-firewalld-custom.rules文件</li>
 *     <li>2.2 写入规则（假设当前用户为hedeoer）,对org.fedoraproject.FirewallD1所有请求放行</li>
 * </ul>

 * <pre>
 *     polkit.addRule(function(action, subject) {
 * if (action.id.indexOf("org.fedoraproject.FirewallD1") == 0 &&
 *         subject.user == "hedeoer") {
 *         return polkit.Result.YES;
 *     }
 * });
 * </pre>
 * <p>3. 验证授权是否生效</p>
 *
 */
public class FirewallPolicyConfigurer {

    private static final Logger logger = LoggerFactory.getLogger(FirewallPolicyConfigurer.class);

    private static final String POLKIT_RULES_DIR = "/etc/polkit-1/rules.d";
    private static final String CUSTOM_RULE_FILE = "90-firewalld-custom.rules";
    private static final String POLICY_TEMPLATE = 
            "polkit.addRule(function(action, subject) {\n" +
            "    if (action.id.indexOf(\"org.fedoraproject.FirewallD1\") == 0 &&\n" +
            "        subject.user == \"%s\") {\n" +
            "        return polkit.Result.YES;\n" +
            "    }\n" +
            "});\n";

    /**
     * 配置防火墙授权策略
     * @return 是否成功配置
     */
    public static boolean configureFirewallPolicy() {
        try {
            // 1. 检查当前用户
            String currentUser = getCurrentUser();
            logger.info("当前用户: {}",currentUser);
            // 检查是否需要授权
            if (!checkFirewallAuthorization()) {


                // 2. 创建策略文件内容
                String policyContent = String.format(POLICY_TEMPLATE, currentUser);

                // 3. 临时创建策略文件
                Path tempPolicyFile = createTempPolicyFile(policyContent);

                // 4. 使用sudo移动文件到策略目录
                boolean moveSuccess = movePolicyFileWithSudo(tempPolicyFile);
                if (!moveSuccess) {
                    logger.error("无法移动策略文件到 {}", POLKIT_RULES_DIR);
                    return false;
                }

                // 5. 重启polkit服务
                boolean restartSuccess = restartPolkitWithSudo();
                if (!restartSuccess) {
                    logger.error("无法重启 polkit 服务");
                    return false;
                }

                logger.info("已成功为用户 '{}' 配置防火墙授权策略", currentUser);
            }
            // 检查授权是否成功
            return checkFirewallAuthorization();

        } catch (Exception e) {
            logger.error("配置防火墙授权策略时发生错误: {}", e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    
    /**
     * 获取当前系统用户名
     */
    private static String getCurrentUser() {
        return System.getProperty("user.name");
    }
    
    /**
     * 创建临时策略文件
     */
    private static Path createTempPolicyFile(String content) throws IOException {
        Path tempFile = Files.createTempFile("firewall-policy-", ".rules");
        Files.write(tempFile, content.getBytes(), StandardOpenOption.WRITE);
        // 确保文件权限正确
        tempFile.toFile().setReadable(true, false);
        return tempFile;
    }
    
    /**
     * 使用sudo移动策略文件到指定目录
     */
    private static boolean movePolicyFileWithSudo(Path tempFile) {
        try {
            String targetPath = POLKIT_RULES_DIR + "/" + CUSTOM_RULE_FILE;
            
            // 检查目标目录是否存在，如果不存在则创建
            ensureDirectoryExistsWithSudo(POLKIT_RULES_DIR);
            
            // 移动文件
            ProcessResult result = new ProcessExecutor()
                    .command("sudo", "cp", tempFile.toString(), targetPath)
                    .readOutput(true)
                    .exitValueNormal()
                    .execute();
            
            // 设置正确的文件权限
            new ProcessExecutor()
                    .command("sudo", "chmod", "644", targetPath)
                    .exitValueNormal()
                    .execute();
                    
            // 清理临时文件
            Files.deleteIfExists(tempFile);
            
            return result.getExitValue() == 0;
        } catch (Exception e) {
            logger.error("移动策略文件失败: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * 确保目录存在，如果不存在则创建
     */
    private static void ensureDirectoryExistsWithSudo(String directory) throws IOException, InterruptedException, TimeoutException {
        File dir = new File(directory);
        if (!dir.exists()) {
            new ProcessExecutor()
                    .command("sudo", "mkdir", "-p", directory)
                    .exitValueNormal()
                    .execute();
                    
            new ProcessExecutor()
                    .command("sudo", "chmod", "755", directory)
                    .exitValueNormal()
                    .execute();
        }
    }
    
    /**
     * 使用sudo重启polkit服务
     */
    private static boolean restartPolkitWithSudo() {
        try {
            // 适用于大多数现代Linux发行版
            ProcessResult result = new ProcessExecutor()
                    .command("sudo", "systemctl", "restart", "polkit")
                    .readOutput(true)
                    .exitValueNormal()
                    .execute();
                    
            // 如果上述命令失败，尝试其他可能的服务名
            if (result.getExitValue() != 0) {
                return tryAlternativePolkitRestart();
            }
            
            return true;
        } catch (Exception e) {
            // 第一种方法失败，尝试替代方法
            return tryAlternativePolkitRestart();
        }
    }
    
    /**
     * 尝试替代方法重启polkit服务
     */
    private static boolean tryAlternativePolkitRestart() {
        try {
            // 不同的Linux发行版可能有不同的服务名
            String[] possibleServiceNames = {
                "polkit.service",
                "polkitd.service",
                "polkit-1.service",
                "policykit.service"
            };
            
            for (String serviceName : possibleServiceNames) {
                try {
                    ProcessResult result = new ProcessExecutor()
                            .command("sudo", "systemctl", "restart", serviceName)
                            .readOutput(true)
                            .exitValueNormal()
                            .execute();
                    
                    if (result.getExitValue() == 0) {
                        return true;
                    }
                } catch (Exception ignored) {
                    // 继续尝试下一个服务名
                }
            }
            
            // 如果所有systemctl命令都失败，尝试手动重载规则
            return reloadPolkitRules();
        } catch (Exception e) {
            logger.error("重启polkit服务失败: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * 尝试手动重载polkit规则
     */
    private static boolean reloadPolkitRules() {
        try {
            // 在某些系统上，需要kill -HUP 来重载规则
            ProcessResult pkillResult = new ProcessExecutor()
                    .command("sudo", "pkill", "-HUP", "polkit")
                    .readOutput(true)
                    .execute();
                    
            // 即使pkill返回非零值（可能找不到进程），也可能成功
            return true;
        } catch (Exception e) {
            logger.error("重载polkit规则失败: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * 检查当前用户是否已获得FirewallD授权
     */
    private static boolean checkFirewallAuthorization() {
        try {
            // 尝试执行一个简单的防火墙命令来测试授权
            ProcessResult result = new ProcessExecutor()
                    .command("firewall-cmd", "--state")
                    .readOutput(true)
                    .timeout(5000, TimeUnit.MILLISECONDS)
                    .execute();
                    
            return result.getExitValue() == 0;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * 使用示例
     */
    public static void main(String[] args) {
        String currentUser = getCurrentUser();
        System.out.println("为用户 '" + currentUser + "' 配置防火墙授权...");
        
        if (checkFirewallAuthorization()) {
            System.out.println("用户已经拥有防火墙操作授权，无需配置。");
        } else {
            boolean success = configureFirewallPolicy();
            if (success) {
                System.out.println("授权配置成功！");
                
                // 验证授权是否生效
                if (checkFirewallAuthorization()) {
                    System.out.println("授权已生效，可以操作防火墙。");
                } else {
                    System.out.println("授权配置完成，但可能需要重新登录才能生效。");
                }
            } else {
                System.err.println("授权配置失败，请手动配置或以root用户运行。");
            }
        }
    }
}
