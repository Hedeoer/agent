package cn.hedeoer.util;

import cn.hedeoer.pojo.FireWallType;
import lombok.Data;
import org.zeroturnaround.exec.ProcessExecutor;
import org.zeroturnaround.exec.ProcessResult;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * 防火墙检测工具类, 只提供ufw和firewall检测
 * 用于检测系统中的防火墙工具及其状态
 */
public class FirewallDetector {

    // 超时时间（秒）
    private static final int COMMAND_TIMEOUT = 10;

    /**
     * 检测系统中的防火墙工具及状态
     * 目前只能监测ufw和firewalld
     * @return 包含防火墙检测结果的Map
     */
    public static Map<String, FirewallStatus> detectFirewalls() {
        Map<String, FirewallStatus> result = new HashMap<>();
        
        // 检测不同的防火墙工具
        result.put("ufw", detectUfw());
        result.put("firewalld", detectFirewalld());
        
        return result;
    }
    
    /**
     * 检测是否同时启用了多种防火墙工具
     * @return 如果同时启用了多种防火墙 (> 1)，返回true
     */
    public static boolean hasMultipleFirewallsEnabled() {
        Map<String, FirewallStatus> firewalls = detectFirewalls();
        int enabledCount = 0;
        
        for (FirewallStatus status : firewalls.values()) {
            if (status.isStarted()) {
                enabledCount++;
            }
        }
        
        return enabledCount > 1;
    }
    
    /**
     * 获取已启用的防火墙列表
     * @return 已启用的防火墙名称列表
     */
    public static List<String> getEnabledFirewalls() {
        Map<String, FirewallStatus> firewalls = detectFirewalls();
        List<String> enabledFirewalls = new ArrayList<>();
        
        for (Map.Entry<String, FirewallStatus> entry : firewalls.entrySet()) {
            if (entry.getValue().isStarted()) {
                enabledFirewalls.add(entry.getKey());
            }
        }
        
        return enabledFirewalls;
    }
    
    /**
     * 检测UFW防火墙
     * @return UFW防火墙状态
     */
    public static FirewallStatus detectUfw() {
        FirewallStatus status = new FirewallStatus();
        status.setFireWallType(FireWallType.FIREWALLD);
        
        try {
            // 检查ufw是否安装
            ProcessResult installResult = new ProcessExecutor()
                    .command("which", "ufw")
                    .readOutput(true)
                    .timeout(COMMAND_TIMEOUT, java.util.concurrent.TimeUnit.SECONDS)
                    .destroyOnExit()
                    .execute();
            
            boolean installed = installResult.getExitValue() == 0;
            status.setInstalled(installed);
            
            if (installed) {
                // 检查ufw是否启用
                ProcessResult statusResult = new ProcessExecutor()
                        .command("ufw", "status")
                        .readOutput(true)
                        .timeout(COMMAND_TIMEOUT, java.util.concurrent.TimeUnit.SECONDS)
                        .destroyOnExit()
                        .execute();
                
                String output = statusResult.outputUTF8();
                boolean enabled = output.contains("Status: active");
                status.setStarted(enabled);
                status.setDetails(output);
            }
        } catch (Exception e) {
            status.setError("Error detecting ufw: " + e.getMessage());
        }
        
        return status;
    }
    
    /**
     * 检测Firewalld防火墙
     * @return Firewalld防火墙状态
     */
    public static FirewallStatus detectFirewalld() {
        FirewallStatus status = new FirewallStatus();
        status.setFireWallType(FireWallType.FIREWALLD);
        
        try {
            // 检查firewalld是否安装
            ProcessResult installResult = new ProcessExecutor()
                    .command("sudo","which", "firewall-cmd")
                    .readOutput(true)
                    .timeout(COMMAND_TIMEOUT, java.util.concurrent.TimeUnit.SECONDS)
                    .exitValueNormal()
                    .destroyOnExit()
                    .execute();
            
            boolean installed = installResult.getExitValue() == 0;
            status.setInstalled(installed);
            
            if (installed) {
                // 检查firewalld是否正在运行
                // systemctl status firewalld
                ProcessResult runningResult = new ProcessExecutor()
                        .command("sudo","systemctl", "is-active","firewalld" )
                        .readOutput(true)
                        .timeout(COMMAND_TIMEOUT, java.util.concurrent.TimeUnit.SECONDS)
                        .destroyOnExit()
                        .execute();
                
                boolean started = runningResult.getExitValue() == 0 &&
                                 runningResult.outputUTF8().trim().equals("active");
                status.setStarted(started);

                // 监测是否firewalld开机自启动 systemctl is-enabled firewalld
                ProcessResult execute = new ProcessExecutor()
                        .command("sudo","systemctl", "is-enabled", "firewalld")
                        .readOutput(true)
                        .timeout(COMMAND_TIMEOUT, TimeUnit.SECONDS)
                        .destroyOnExit()
                        .execute();
                status.setEnable(execute.outputUTF8().trim());

                // 获取更多详细信息
                if (started) {
                    ProcessResult detailsResult = new ProcessExecutor()
                            .command("sudo","firewall-cmd", "--list-all")
                            .readOutput(true)
                            .timeout(COMMAND_TIMEOUT, java.util.concurrent.TimeUnit.SECONDS)
                            .destroyOnExit()
                            .execute();
                    
                    status.setDetails(detailsResult.outputUTF8());
                }
            }
        } catch (Exception e) {
            status.setError("Error detecting firewalld: " + e.getMessage());
        }
        
        return status;
    }

    
    /**
     * 防火墙状态类
     */
    @Data
    public static class FirewallStatus {
        // 防火墙名字
        private FireWallType fireWallType;
        // 是否已被安装
        private boolean installed;
        // 当前是否启动防火墙
        private boolean started;
        /*
        是否开机自启动
        enabled - 已设置为开机自启动
        disabled - 未设置为开机自启动
        static - 不能直接启用，但可被其他启用的单元自动启动
        masked - 服务被屏蔽，无法启动
        */
        private String enable;
        // 防火墙细节
        private String details;
        // 无法监测防火墙状态的报错信息
        private String error;
    }
    
    /**
     * 生成防火墙状态报告
     * @return 防火墙状态报告
     */
    public static String generateFirewallReport() {
        Map<String, FirewallStatus> firewalls = detectFirewalls();
        List<String> enabledFirewalls = getEnabledFirewalls();
        boolean multipleEnabled = hasMultipleFirewallsEnabled();
        
        StringBuilder report = new StringBuilder();
        report.append("=== 防火墙检测报告 ===\n\n");
        
        // 各防火墙状态
        report.append("检测到的防火墙:\n");
        for (FirewallStatus status : firewalls.values()) {
            report.append("- ").append(status.toString()).append("\n");
            if (status.isStarted() && !status.getDetails().isEmpty()) {
                report.append("  详情: ").append(status.getDetails().replace("\n", "\n  ")).append("\n");
            }
        }
        
        report.append("\n已启用的防火墙: ");
        if (enabledFirewalls.isEmpty()) {
            report.append("无");
        } else {
            report.append(String.join(", ", enabledFirewalls));
        }
        
        report.append("\n\n多重防火墙检测: ");
        if (multipleEnabled) {
            report.append("警告! 系统同时启用了多个防火墙工具，这可能导致冲突或意外的网络行为。");
        } else {
            report.append("正常 (未检测到多个防火墙同时启用)");
        }
        
        return report.toString();
    }

}
