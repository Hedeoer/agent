package cn.hedeoer.ssh;

import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.command.CommandFactory;
import org.apache.sshd.server.shell.ProcessShellFactory;
import org.apache.sshd.server.shell.ShellFactory;

import java.io.IOException;

public class SelfProcessShellCommandFactory implements CommandFactory {
    @Override
    public Command createCommand(ChannelSession channel, String command) throws IOException {

        // 解析 commandLine 字符串来决定创建哪个 Command
        // 例如，可以基于命令的第一个单词，或者使用更复杂的参数解析
        String[] parts = command.trim().split("\\s+", 2); // 按第一个空格分割
        String commandName = parts[0].toLowerCase(); // 命令名不区分大小写

        switch (commandName) {
            case "get_ssh_server_status":
                return new CheckAgentRunningStatusCommand(command);

            default:
                ShellFactory factory = new ProcessShellFactory(command, CommandFactory.split(command));
                return factory.createShell(channel);
        }
    }
}
