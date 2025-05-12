package cn.hedeoer.ssh; // 假设包名

import org.apache.sshd.common.session.SessionHeartbeatController;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.config.keys.DefaultAuthorizedKeysAuthenticator;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.shell.ProcessShellCommandFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.Security;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * ssh 服务器的启动和授权
 */
public class SimpleSshServerWithPublicKeyAuth {

    private static final Logger logger = LoggerFactory.getLogger(SimpleSshServerWithPublicKeyAuth.class);


    // authorized_keys 文件的路径
    // 确保这个文件存在，并且包含客户端的公钥 (例如 id_rsa.pub 的内容)
    private static final Path AUTHORIZED_KEYS_PATH = Paths.get(System.getProperty("user.home"), ".ssh", "authorized_keys");
    // ssh服务器的主机密钥存放位置
    private static final Path HOST_PRIVATE_KEY_PATH = Paths.get(System.getProperty("user.home"), ".ssh", "hostkey.ser");
    // ssh 服务端默认需要开放的端口
    private Integer defaultSshServerPort;
    // 需要验证的公钥
    private String needCheckPublicKey;


    public SimpleSshServerWithPublicKeyAuth() {
    }

    public SimpleSshServerWithPublicKeyAuth(Integer defaultSshServerPort,String needCheckPublicKey) {
        this.defaultSshServerPort = defaultSshServerPort;
        this.needCheckPublicKey = needCheckPublicKey;
    }

    /**
     * 检查 authorized_keys 文件是否存在。
     * 如果不存在，则创建文件和必要的父目录，并设置推荐的权限，然后将指定的客户端公钥写入文件。
     * 如果文件已存在，则检查该公钥是否已在文件中，如果不在，则追加该公钥。
     * @return 如果操作成功（文件创建/更新或公钥已存在），则返回 true；否则返回 false。
     */
    private boolean ensureAuthorizedKeyExists() {
        if (needCheckPublicKey == null || needCheckPublicKey.trim().isEmpty()) {
            logger.error("Client public key cannot be null or empty.");
            return false;
        }

        // 清理公钥字符串，确保是一行且没有多余的空白
        String cleanPublicKey = needCheckPublicKey.trim();

        try {
            Path parentDir = AUTHORIZED_KEYS_PATH.getParent();

            // 1. 确保父目录存在并设置权限 (0700)
            if (parentDir != null) {
                if (!Files.exists(parentDir)) {
                    try {
                        // 尝试创建具有 POSIX 权限的目录
                        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rwx------");
                        FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(perms);
                        Files.createDirectories(parentDir, attr); // createDirectories 会创建所有不存在的父目录
                        logger.info("Server: Created directory {} with permissions rwx------.", parentDir);
                        // 在非 POSIX 系统上，权限设置可能无效或被忽略，但创建目录仍会尝试
                    } catch (UnsupportedOperationException e) {
                        // 文件系统不支持 POSIX 权限
                        Files.createDirectories(parentDir);
                        logger.info("Server: Created directory {} (POSIX permissions not supported/set).", parentDir);
                    } catch (IOException e) {
                        logger.error("Server: Failed to create directory {}: {}", parentDir, e.getMessage(), e);
                        return false;
                    }
                } else {
                    // 如果目录已存在，可选：检查并设置权限
                    try {
                        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rwx------");
                        Files.setPosixFilePermissions(parentDir, perms);
                        // logger.debug("Server: Ensured directory {} permissions are rwx------.", parentDir);
                    } catch (UnsupportedOperationException e) {
                        // 文件系统不支持 POSIX 权限，忽略
                    } catch (IOException e) {
                        logger.warn("Server: Could not set permissions for directory {}: {}. Continuing...", parentDir, e.getMessage());
                    }
                }
            }

            // 2. 处理 authorized_keys 文件
            if (!Files.exists(AUTHORIZED_KEYS_PATH)) {
                // 文件不存在，创建并写入公钥，设置权限 (0600)
                try {
                    // 确保公钥末尾有换行符
                    String contentToWrite = cleanPublicKey.endsWith("\n") ? cleanPublicKey : cleanPublicKey + "\n";
                    Files.write(AUTHORIZED_KEYS_PATH, contentToWrite.getBytes(StandardCharsets.UTF_8),
                            StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE); // CREATE_NEW 确保是新创建
                    logger.info("Server: Created {} and added client public key.", AUTHORIZED_KEYS_PATH);

                    // 设置文件权限
                    try {
                        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
                        Files.setPosixFilePermissions(AUTHORIZED_KEYS_PATH, perms);
                        logger.info("Server: Set {} permissions to rw-------.", AUTHORIZED_KEYS_PATH);
                    } catch (UnsupportedOperationException e) {
                        // 文件系统不支持 POSIX 权限，忽略
                        logger.info("Server: {} created (POSIX permissions not supported/set).", AUTHORIZED_KEYS_PATH);
                    } catch (IOException e) {
                        logger.warn("Server: Could not set permissions for {}: {}. Continuing...", AUTHORIZED_KEYS_PATH, e.getMessage());
                    }
                    return true;

                } catch (IOException e) {
                    logger.error("Server: Failed to create and write to {}: {}", AUTHORIZED_KEYS_PATH, e.getMessage(), e);
                    return false;
                }
            } else {
                // 文件已存在，检查公钥是否已在其中，如果不在则追加
                try {
                    Set<String> existingKeys = new HashSet<>();
                    // 读取现有所有行，并去除空白字符和注释
                    if (Files.size(AUTHORIZED_KEYS_PATH) > 0) { // 避免读取空文件导致的问题
                        try (BufferedReader reader = new BufferedReader(new InputStreamReader(Files.newInputStream(AUTHORIZED_KEYS_PATH), StandardCharsets.UTF_8))) {
                            String line;
                            while ((line = reader.readLine()) != null) {
                                String trimmedLine = line.trim();
                                if (!trimmedLine.isEmpty() && !trimmedLine.startsWith("#")) {
                                    existingKeys.add(trimmedLine);
                                }
                            }
                        }
                    }

                    if (existingKeys.contains(cleanPublicKey)) {
                        logger.info("Server: Client public key already exists in {}.", AUTHORIZED_KEYS_PATH);
                        return true;
                    } else {
                        // 追加公钥，确保有换行符
                        String contentToAppend = cleanPublicKey.endsWith("\n") ? cleanPublicKey : cleanPublicKey + "\n";
                        // 使用 BufferedWriter 以追加模式写入
                        try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                                Files.newOutputStream(AUTHORIZED_KEYS_PATH, StandardOpenOption.APPEND, StandardOpenOption.WRITE),
                                StandardCharsets.UTF_8))) {
                            writer.write(contentToAppend);
                        }
                        logger.info("Server: Appended client public key to {}.", AUTHORIZED_KEYS_PATH);

                        // 可选：确保文件权限在追加后仍然正确 (有些系统追加操作可能影响权限)
                        try {
                            Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
                            Files.setPosixFilePermissions(AUTHORIZED_KEYS_PATH, perms);
                        } catch (UnsupportedOperationException | IOException ignored) {
                            // 忽略权限设置失败
                        }
                        return true;
                    }
                } catch (IOException e) {
                    logger.error("Server: Failed to read or append to {}: {}", AUTHORIZED_KEYS_PATH, e.getMessage(), e);
                    return false;
                }
            }
        } catch (Exception e) { // 捕获任何意外异常
            logger.error("Server: An unexpected error occurred while ensuring authorized key exists: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * 用于启动ssh服务器
     *
     * @return 启动成功 返回true
     */
    public Boolean startSshServer() {

        try {
            // 扩展了 SSHD 的加密能力，使其能够支持更多、更现代、更安全的加密算法和密钥类型，此处主要使用Ed25519
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new BouncyCastleProvider());
                logger.info("Server: BouncyCastle provider registered.");
            }

            // 创建 authorized_keys 文件 (如果不存在)
            if (!ensureAuthorizedKeyExists()) {
                return false;
            }

            SshServer sshd = SshServer.setUpDefaultServer();
            sshd.setPort(defaultSshServerPort);

            // 服务器自身的主机密钥，用于向客户端证明自己的身份
            // SSH 服务器主机密钥的提供者和管理者
            // 从指定路径加载主机密钥。
            // 如果密钥文件不存在，则生成新的主机密钥。
            // 将主机密钥以 OpenSSH 兼容格式持久化到文件系统。
            sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(HOST_PRIVATE_KEY_PATH));

            // 设置公钥认证器
            // AUTHORIZED_KEYS_PATH 授权文件位置
            // strict为 true : makes sure that the containing folder has 0700 access and the file 0600
            // NOFOLLOW_LINKS：自动跟随符号链接。这意味着操作会作用于链接指向的最终目标
            sshd.setPublickeyAuthenticator(new DefaultAuthorizedKeysAuthenticator(AUTHORIZED_KEYS_PATH, false, LinkOption.NOFOLLOW_LINKS));


            // 自定义的Command
            sshd.setCommandFactory(new SelfProcessShellCommandFactory());   // 用于 exec channel

            // 设置全局的服务器端心跳，例如每60秒发送一次心跳
            sshd.setSessionHeartbeat(SessionHeartbeatController.HeartbeatType.IGNORE, TimeUnit.SECONDS, 60L);


            sshd.start();
            logger.info("Server: Started SSH server.");
            return true;
        } catch (IOException e) {
            logger.error("Server: Failed to start SSH server.");
            return false;
        }
    }
}