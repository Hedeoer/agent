package cn.hedeoer;

import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import org.zeroturnaround.exec.ProcessExecutor;
import org.zeroturnaround.exec.ProcessResult;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeoutException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class UFWPortScanner {
    private static final Pattern PORT_PATTERN = Pattern.compile("(\\d+)/(?:tcp|udp)");
    // 本地执行UFW命令
    public static List<Integer> getOpenPortsLocal() throws IOException, InterruptedException, TimeoutException {
        ProcessResult result = new ProcessExecutor()
                .command("ufw", "status")
                .readOutput(true)
                .execute();
        return parseUfwOutput(result.outputUTF8());
    }
    // 通过JSch执行SSH命令（密码方式）
    public static List<Integer> getOpenPortsViaSSH(String host, String username, String password)
            throws JSchException, IOException {

        JSch jsch = new JSch();
        Session session = null;

        try {
            session = jsch.getSession(username, host, 22);
            session.setPassword(password);

            // 不验证主机密钥
            java.util.Properties config = new java.util.Properties();
            config.put("StrictHostKeyChecking", "no");
            session.setConfig(config);

            session.connect(30000); // 超时时间为30秒

            String command = "sudo ufw status";
            String output = executeCommand(session, command);

            return parseUfwOutput(output);
        } finally {
            if (session != null && session.isConnected()) {
                session.disconnect();
            }
        }
    }
    // 使用SSH密钥的方式
    public static List<Integer> getOpenPortsViaSSHKey(String host, String username, String keyPath)
            throws JSchException, IOException {

        JSch jsch = new JSch();
        jsch.addIdentity(keyPath);
        Session session = null;

        try {
            session = jsch.getSession(username, host, 22);

            // 不验证主机密钥
            java.util.Properties config = new java.util.Properties();
            config.put("StrictHostKeyChecking", "no");
            session.setConfig(config);

            session.connect(30000); // 超时时间为30秒

            String command = "sudo ufw status";
            String output = executeCommand(session, command);

            return parseUfwOutput(output);
        } finally {
            if (session != null && session.isConnected()) {
                session.disconnect();
            }
        }
    }

    // 在SSH会话中执行命令
    private static String executeCommand(Session session, String command) throws JSchException, IOException {
        ChannelExec channel = null;
        try {
            channel = (ChannelExec) session.openChannel("exec");
            channel.setCommand(command);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            ByteArrayOutputStream errorStream = new ByteArrayOutputStream();

            channel.setOutputStream(outputStream);
            channel.setErrStream(errorStream);

            channel.connect(10000); // 超时时间为10秒

            // 等待命令执行完成
            while (channel.isConnected()) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }

            // 如果有错误输出，打印它
            if (errorStream.size() > 0) {
                System.err.println("Error output: " + errorStream.toString());
            }

            return outputStream.toString();
        } finally {
            if (channel != null && channel.isConnected()) {
                channel.disconnect();
            }
        }
    }
    // 解析UFW输出，提取开放的端口
    private static List<Integer> parseUfwOutput(String output) {
        List<Integer> openPorts = new ArrayList<>();

        // 检查UFW是否启用
        if (output.contains("Status: inactive")) {
            System.out.println("UFW is inactive");
            return openPorts;
        }
        // 提取所有ALLOW的端口
        String[] lines = output.split("\n");
        for (String line : lines) {
            if (line.contains("ALLOW") || line.contains("允许")) {
                Matcher matcher = PORT_PATTERN.matcher(line);
                while (matcher.find()) {
                    openPorts.add(Integer.parseInt(matcher.group(1)));
                }
            }
        }

        return openPorts;
    }
    // 添加端口规则
    public static void allowPort(String host, String username, String password, int port, String protocol)
            throws JSchException, IOException {
        JSch jsch = new JSch();
        Session session = null;

        try {
            session = jsch.getSession(username, host, 22);
            session.setPassword(password);

            java.util.Properties config = new java.util.Properties();
            config.put("StrictHostKeyChecking", "no");
            session.setConfig(config);

            session.connect(30000);

            String command = "sudo ufw allow " + port + "/" + protocol;
            executeCommand(session, command);
        } finally {
            if (session != null && session.isConnected()) {
                session.disconnect();
            }
        }
    }
    // 检查UFW状态
    public static boolean isUfwActive(String host, String username, String password)
            throws JSchException, IOException {
        JSch jsch = new JSch();
        Session session = null;

        try {
            session = jsch.getSession(username, host, 22);
            session.setPassword(password);

            java.util.Properties config = new java.util.Properties();
            config.put("StrictHostKeyChecking", "no");
            session.setConfig(config);

            session.connect(30000);

            String command = "sudo ufw status | grep Status";
            String output = executeCommand(session, command);

            return output.contains("active");
        } finally {
            if (session != null && session.isConnected()) {
                session.disconnect();
            }
        }
    }
    public static void main(String[] args) {
        try {
            // 使用JSch连接SSH
            System.out.println("\n查询远程服务器UFW开放端口（密码方式）：");
            List<Integer> remotePorts = getOpenPortsViaSSH("192.168.2.99", "hedeoer", "hedeoer123");
            printPorts(remotePorts);

            // 使用密钥方式也可以
            /*
            System.out.println("\n查询远程服务器UFW开放端口（密钥方式）：");
            List<Integer> remoteKeyPorts = getOpenPortsViaSSHKey("192.168.2.99", "hedeoer", "C:/path/to/private_key");
            printPorts(remoteKeyPorts);
            */

        } catch (Exception e) {
            System.err.println("执行失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void printPorts(List<Integer> ports) {
        if (ports.isEmpty()) {
            System.out.println("未发现开放端口");
        } else {
            System.out.println("开放端口列表:");
            for (Integer port : ports) {
                System.out.println("- " + port);
            }
        }
    }
}
