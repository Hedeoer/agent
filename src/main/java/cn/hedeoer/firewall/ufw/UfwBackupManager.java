package cn.hedeoer.firewall.ufw; // 你的包名

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zeroturnaround.exec.ProcessExecutor;
import org.zeroturnaround.exec.ProcessResult;
import org.zeroturnaround.exec.stream.slf4j.Slf4jStream;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class UfwBackupManager {

    private static final Logger logger = LoggerFactory.getLogger(UfwBackupManager.class);

    private static final String BACKUP_DIR_PATH = "/var/tmp/";
    private static final String UFW_CONFIG_DIR = "/etc/ufw/";

    private static final String USER_RULES_FILE = "user.rules";
    private static final String USER6_RULES_FILE = "user6.rules";
    private static final String BEFORE_RULES_FILE = "before.rules";
    private static final String AFTER_RULES_FILE = "after.rules";
    private static final String SYSCTL_CONF_FILE = "sysctl.conf";
    private static final String DEFAULT_UFW_CONF_FILE = "/etc/default/ufw";

    private static final int DEFAULT_TIMEOUT_SECONDS = 30;

    private static final List<String> FILES_TO_BACKUP = Arrays.asList(
            USER_RULES_FILE,
            USER6_RULES_FILE,
            BEFORE_RULES_FILE,
            AFTER_RULES_FILE,
            SYSCTL_CONF_FILE,
            DEFAULT_UFW_CONF_FILE
    );

    private static String getBackupFilePath(String originalFileName) {
        File originalFile = new File(originalFileName);
        return Paths.get(BACKUP_DIR_PATH, originalFile.getName() + ".backup").toString();
    }

    /**
     * 执行UFW配置文件的备份。
     *
     * @return 如果所有相关文件的备份都成功（或文件不存在而跳过），则返回 true；否则返回 false。
     */
    public static boolean backupUfwConfiguration() {
        logger.info("Starting UFW configuration backup...");
        boolean allSuccessful = true;

        File backupDir = new File(BACKUP_DIR_PATH);
        if (!backupDir.exists()) {
            if (!backupDir.mkdirs()) {
                logger.error("Failed to create backup directory: {}", BACKUP_DIR_PATH);
                return false; // 目录创建失败，无法继续
            }
            logger.info("Backup directory created: {}", BACKUP_DIR_PATH);
        }

        for (String fileName : FILES_TO_BACKUP) {
            String sourcePath;
            if (Paths.get(fileName).isAbsolute()) {
                sourcePath = fileName;
            } else {
                sourcePath = Paths.get(UFW_CONFIG_DIR, fileName).toString();
            }
            String backupPath = getBackupFilePath(new File(sourcePath).getName());

            File sourceFile = new File(sourcePath);
            if (sourceFile.exists() && sourceFile.isFile()) {
                logger.debug("Backing up {} to {}", sourcePath, backupPath);
                try {
                    executeCommand("sudo", "cp", "-p", sourcePath, backupPath);
                } catch (IOException | InterruptedException | TimeoutException | RuntimeException e) {
                    logger.warn("Failed to backup {}: {}. This file might not be critical or exist.", sourcePath, e.getMessage());
                    // 对于 user.rules 或 default/ufw 的失败，我们认为整个备份操作失败
                    if (fileName.equals(USER_RULES_FILE) || fileName.equals(DEFAULT_UFW_CONF_FILE)) {
                        allSuccessful = false;
                    }
                    // 对于其他可选文件，可以选择不将 allSuccessful 置为 false，只记录警告
                }
            } else {
                logger.info("UFW configuration file not found, skipping backup: {}", sourcePath);
                // 如果是关键文件 user.rules 不存在，也应该标记备份不完全成功
                if (fileName.equals(USER_RULES_FILE) || fileName.equals(DEFAULT_UFW_CONF_FILE)) {
                    logger.warn("Critical UFW configuration file {} not found. Backup may be incomplete.", sourcePath);
                    // allSuccessful = false; // 取决于策略，如果关键文件不存在是否算成功
                }
            }
        }

        if (allSuccessful) {
            logger.info("UFW configuration backup completed successfully.");
        } else {
            logger.error("UFW configuration backup process encountered errors or critical files were not backed up.");
        }
        return allSuccessful;
    }

    /**
     * 删除之前创建的UFW配置文件备份。
     *
     * @return 如果所有存在的备份文件都被成功删除（或备份文件本就不存在），则返回 true；
     *         如果在删除任何一个存在的备份文件时失败，则返回 false。
     */
    public static boolean deleteBackupFiles() {
        logger.info("Deleting UFW configuration backup files...");
        boolean allDeletionsSuccessful = true;

        for (String fileName : FILES_TO_BACKUP) {
            String backupPath = getBackupFilePath(new File(fileName).getName());
            File backupFile = new File(backupPath);
            if (backupFile.exists()) {
                try {
                    executeCommand("sudo", "rm", "-f", backupPath);
                    logger.debug("Deleted backup file: {}", backupPath);
                } catch (IOException | InterruptedException | TimeoutException | RuntimeException e) {
                    logger.warn("Failed to delete backup file {}: {}", backupPath, e.getMessage());
                    allDeletionsSuccessful = false; // 任何一个删除失败都标记为整体失败
                }
            } else {
                logger.debug("Backup file not found, no need to delete: {}", backupPath);
            }
        }

        if (allDeletionsSuccessful) {
            logger.info("UFW configuration backup files deletion completed successfully.");
        } else {
            logger.warn("Some UFW configuration backup files could not be deleted.");
        }
        return allDeletionsSuccessful;
    }

    /**
     * 使用之前备份的配置文件恢复UFW，并重新加载UFW。
     *
     * @return 如果所有关键配置文件的恢复以及 `ufw reload` 都成功，则返回 true；否则返回 false。
     */
    public static boolean restoreUfwConfigurationAndReload() {
        logger.info("Starting UFW configuration restore and reload...");
        boolean criticalFileRestored = false;
        boolean allRestoresSuccessful = true;

        for (String fileName : FILES_TO_BACKUP) {
            String targetPath;
            if (Paths.get(fileName).isAbsolute()) {
                targetPath = fileName;
            } else {
                targetPath = Paths.get(UFW_CONFIG_DIR, fileName).toString();
            }
            String backupPath = getBackupFilePath(new File(targetPath).getName());

            File backupFile = new File(backupPath);
            if (backupFile.exists() && backupFile.isFile()) {
                logger.debug("Restoring {} from {}", targetPath, backupPath);
                try {
                    executeCommand("sudo", "cp", "-p", backupPath, targetPath);
                    if (fileName.equals(USER_RULES_FILE) || fileName.equals(DEFAULT_UFW_CONF_FILE)) {
                        criticalFileRestored = true; // 标记至少一个关键文件已尝试恢复
                    }
                } catch (IOException | InterruptedException | TimeoutException | RuntimeException e) {
                    logger.error("Failed to restore {}: {}. UFW might be in an inconsistent state.", targetPath, e.getMessage());
                    allRestoresSuccessful = false; // 任何一个文件恢复失败都标记
                    if (fileName.equals(USER_RULES_FILE) || fileName.equals(DEFAULT_UFW_CONF_FILE)) {
                        logger.error("Critical UFW configuration file {} restore failed.", targetPath);
                        // 对于关键文件恢复失败，可以直接返回 false
                        return false;
                    }
                }
            } else {
                logger.warn("Backup file for {} not found. Skipping restore for this file.", targetPath);
                // 如果是关键文件的备份不存在，这通常是个问题
                if (fileName.equals(USER_RULES_FILE) || fileName.equals(DEFAULT_UFW_CONF_FILE)) {
                    logger.error("Critical UFW configuration file {} backup not found. Cannot fully restore.", targetPath);
                    allRestoresSuccessful = false;
                    // 根据策略，如果关键备份文件不存在，可能也应该立即返回 false
                    // return false;
                }
            }
        }

        if (!allRestoresSuccessful) {
            logger.error("One or more UFW configuration files could not be restored from backup. Aborting reload.");
            return false;
        }

        if (!criticalFileRestored && !new File(Paths.get(UFW_CONFIG_DIR, USER_RULES_FILE).toString()).exists()) {
            logger.error("Critical UFW configuration file {} was not restored (backup missing or restore failed) and original does not exist. Aborting reload.", USER_RULES_FILE);
            return false;
        }


        logger.info("UFW configuration files restored. Attempting to reload UFW...");
        try {
            executeCommand("sudo", "ufw", "reload");
            logger.info("UFW reloaded successfully. Rules should be active as per restored configuration.");
        } catch (IOException | InterruptedException | TimeoutException | RuntimeException e) {
            logger.error("Failed to reload UFW after restoring configuration: {}. Firewall might be in an unexpected state.", e.getMessage());
            return false; // ufw reload 失败是严重问题
        }

        logger.info("UFW configuration restore and reload process completed successfully.");
        return true;
    }


    private static void executeCommand(String... commandParts)
            throws IOException, InterruptedException, TimeoutException {
        // 这个方法的实现与之前相同，如果命令失败会抛出 RuntimeException
        // 在调用它的地方，我们会捕获这个 RuntimeException (以及其他受检异常)
        // 并据此判断操作是否成功

        ProcessExecutor executor = new ProcessExecutor().command(commandParts);
        executor.redirectError(Slf4jStream.of(logger).asError())
                .redirectOutput(Slf4jStream.of(logger).asDebug());

        ProcessResult result = executor
                .timeout(DEFAULT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .execute();

        if (result.getExitValue() != 0) {
            String errorMessage = String.format("Command '%s' failed with exit code %d.",
                    String.join(" ", commandParts), result.getExitValue());
            logger.error(errorMessage + " STDOUT (if any): " + result.outputUTF8());
            throw new RuntimeException(errorMessage); // 明确抛出运行时异常，由调用者捕获
        }
        logger.debug("Command '{}' executed successfully.", String.join(" ", commandParts));
    }


    // --- 主方法用于测试 (可选) ---
    public static void main(String[] args) {
        // System.setProperty(org.slf4j.impl.SimpleLogger.DEFAULT_LOG_LEVEL_KEY, "DEBUG");
        System.out.println("--- Test UFW Configuration Backup and Restore ---");

        // 1. 备份
        System.out.println("\nStep 1: Backing up UFW configuration...");
        boolean backupSuccess = UfwBackupManager.backupUfwConfiguration();
        if (backupSuccess) {
            System.out.println("Backup process reported success.");
            System.out.println("Backup files are in: " + BACKUP_DIR_PATH);
        } else {
            System.err.println("Backup process reported failure. Check logs.");
            return; // 如果备份失败，后续测试可能无意义
        }

        // 2. 模拟修改
        System.out.println("\nStep 2: Simulating a UFW rule change (deleting rule 1)...");
        boolean ruleChangeSuccess = false;
        try {
            new ProcessExecutor()
                    .command("sudo", "ufw", "--force", "delete", "1")
                    .timeout(10, TimeUnit.SECONDS)
                    .exitValueNormal()
                    .execute();
            System.out.println("Rule [1] (if existed) deleted for testing purposes.");
            ruleChangeSuccess = true;
        } catch (Exception e) {
            logger.error("Failed to delete UFW rule for testing: {}", e.getMessage(), e);
            System.err.println("Failed to delete UFW rule for testing.");
        }
        if (!ruleChangeSuccess) {
            System.err.println("Skipping restore test as rule change failed.");
        } else {
            System.out.println("Waiting for 5 seconds before restoring...");
            try { TimeUnit.SECONDS.sleep(5); } catch (InterruptedException ignored) {}

            // 3. 恢复
            System.out.println("\nStep 3: Restoring UFW configuration from backup and reloading...");
            boolean restoreSuccess = UfwBackupManager.restoreUfwConfigurationAndReload();
            if (restoreSuccess) {
                System.out.println("Restore and reload process reported success.");
                System.out.println("Run `sudo ufw status numbered` in another terminal to verify.");
            } else {
                System.err.println("Restore and reload process reported failure. Check logs. Firewall might be in an inconsistent state.");
            }
            System.out.println("Waiting for 5 seconds before cleaning up...");
            try { TimeUnit.SECONDS.sleep(5); } catch (InterruptedException ignored) {}

        }


        // 4. 清理
        System.out.println("\nStep 4: Cleaning up backup files...");
        boolean deleteSuccess = UfwBackupManager.deleteBackupFiles();
        if (deleteSuccess) {
            System.out.println("Backup files cleanup reported success.");
        } else {
            System.err.println("Backup files cleanup reported failure. Check logs.");
        }

        System.out.println("\nTest finished.");
    }
}