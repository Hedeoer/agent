package cn.hedeoer.ssh;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.command.AbstractCommandSupport;
import org.apache.sshd.server.session.ServerSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.stream.Collectors;

public class CheckAgentRunningStatusCommand extends AbstractCommandSupport {
    private static final Logger log = LoggerFactory.getLogger(CheckAgentRunningStatusCommand.class); // 使用规范的 log 变量名

    public CheckAgentRunningStatusCommand(String command) {
        super(command, null); // 假设使用默认的单线程执行器
    }

    // 如果确实需要外部传入执行器，可以保留这个构造函数
    // protected CheckAgentRunningStatusCommand(String command, CloseableExecutorService executorService) {
    //     super(command, executorService);
    // }

    @Override
    public void run() {
        // InputStream in = getInputStream(); // 当前命令似乎不需要输入
        OutputStream out = getOutputStream();
        OutputStream err = getErrorStream();

        try {
            log.info("Executing command: {}", getCommand());

            ServerSession serverSession = getServerSession();
            if (serverSession == null) {
                log.error("ServerSession is null, cannot retrieve SshServer info for command: {}", getCommand());
                // 直接通过 err 输出错误信息，然后调用 onExit
                err.write("Internal server error: session not available\n".getBytes(StandardCharsets.UTF_8));
                err.flush();
                onExit(1, "Internal server error: session not available");
                return; // 必须返回，避免后续执行
            }

            SshServerInfo sshServerInfo = getSshServerInfo(serverSession);
            if (sshServerInfo == null) {
                // getSshServerInfo 内部应该已经记录了错误
                err.write("Failed to retrieve SSH server information.\n".getBytes(StandardCharsets.UTF_8));
                err.flush();
                onExit(2, "Failed to retrieve SSH server information");
                return;
            }

            ObjectMapper mapper = new ObjectMapper();
            String statusJson = mapper.writeValueAsString(sshServerInfo);

            out.write(statusJson.getBytes(StandardCharsets.UTF_8));
            out.flush();
            log.info("Executed command: {}", getCommand());
            onExit(0, "Command completed successfully");

        } catch (JsonProcessingException e) {
            log.error("Error serializing SSH server info to JSON for command {}: {}", getCommand(), e.getMessage(), e);
            try {
                err.write(("Error processing server status (JSON serialization): " + e.getMessage() + "\n").getBytes(StandardCharsets.UTF_8));
                err.flush();
            } catch (IOException ignored) {}
            onExit(3, "JSON serialization error");
        } catch (IOException e) {
            log.error("IOException in command {}: {}", getCommand(), e.getMessage(), e);
            try {
                err.write(("Error executing command: " + e.getMessage() + "\n").getBytes(StandardCharsets.UTF_8));
                err.flush();
            } catch (IOException ignored) {}
            onExit(1, "Command failed with IOException");
        } catch (Exception e) {
            log.error("Unexpected exception in command {}: {}", getCommand(), e.getMessage(), e);
            try {
                err.write(("Unexpected error: " + e.getMessage() + "\n").getBytes(StandardCharsets.UTF_8));
                err.flush();
            } catch (IOException ignored) {}
            onExit(255, "Command failed with unexpected error");
        }
    }

    /**
     * 获取 SSH 服务器的状态信息对象。
     *
     * @param serverSession 当前的服务器会话。
     * @return SshServerInfo 对象，如果无法获取则返回 null。
     */
    private SshServerInfo getSshServerInfo(ServerSession serverSession) {
        FactoryManager factoryManager = serverSession.getFactoryManager();

        if (factoryManager instanceof SshServer) {
            SshServer sshServer = (SshServer) factoryManager;

            String serverVersion = sshServer.getVersion();
            String host = sshServer.getHost();
            Integer serverPort = sshServer.getPort();
            Integer currentActiveSessions = sshServer.getActiveSessions().size();

            Set<String> addresses = sshServer.getBoundAddresses().stream()
                    .map(addr -> {
                        if (addr instanceof SshdSocketAddress) {
                            SshdSocketAddress sshdAddr = (SshdSocketAddress) addr;
                            return sshdAddr.getHostName() + ":" + sshdAddr.getPort();
                        } else {
                            return addr.toString();
                        }
                    })
                    .collect(Collectors.toSet());

            return new SshServerInfo(serverVersion, host, serverPort, currentActiveSessions, addresses);
        } else {
            log.warn("FactoryManager is not an instance of SshServer for session {}. Type: {}", serverSession.getIoSession(), factoryManager.getClass().getName());
            return null; // 表示无法获取 SshServer 实例
        }
    }

    /**
     * SSH服务器信息类，用于封装SSH服务器的基本状态信息。
     * 设为静态内部类，或者如果可能在其他地方使用，则设为顶级类。
     */
    public static class SshServerInfo { // 建议设为 static 内部类或顶级类
        private String serverVersion;
        private String host;
        private Integer serverPort;
        private Integer currentActiveSessions;
        private Set<String> boundAddresses;

        // Jackson 需要一个无参构造函数进行反序列化，尽管这里主要用于序列化
        public SshServerInfo() {}

        public SshServerInfo(String serverVersion, String host, Integer serverPort,
                             Integer currentActiveSessions, Set<String> boundAddresses) {
            this.serverVersion = serverVersion;
            this.host = host;
            this.serverPort = serverPort;
            this.currentActiveSessions = currentActiveSessions;
            this.boundAddresses = boundAddresses;
        }

        // --- Getters and Setters for Jackson serialization/deserialization ---
        public String getServerVersion() { return serverVersion; }
        public void setServerVersion(String serverVersion) { this.serverVersion = serverVersion; }
        public String getHost() { return host; }
        public void setHost(String host) { this.host = host; }
        public Integer getServerPort() { return serverPort; }
        public void setServerPort(Integer serverPort) { this.serverPort = serverPort; }
        public Integer getCurrentActiveSessions() { return currentActiveSessions; }
        public void setCurrentActiveSessions(Integer currentActiveSessions) { this.currentActiveSessions = currentActiveSessions; }
        public Set<String> getBoundAddresses() { return boundAddresses; }
        public void setBoundAddresses(Set<String> boundAddresses) { this.boundAddresses = boundAddresses; }

        @Override
        public String toString() { // toString 主要用于调试，实际输出是JSON
            return "SshServerInfo{" +
                    "serverVersion='" + serverVersion + '\'' +
                    ", host='" + host + '\'' +
                    ", serverPort=" + serverPort +
                    ", currentActiveSessions=" + currentActiveSessions +
                    ", boundAddresses=" + boundAddresses +
                    '}';
        }
    }
}
