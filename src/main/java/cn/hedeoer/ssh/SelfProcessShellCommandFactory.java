package cn.hedeoer.ssh;


import cn.hedeoer.schedule.HeartBeat;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.command.CommandFactory;
import org.apache.sshd.server.shell.ProcessShellFactory;
import org.apache.sshd.server.shell.ShellFactory;

import java.io.IOException;

/**
 * ssh命令执行匹配，按照ssh命令特征执行对应的命令
 */
public class SelfProcessShellCommandFactory implements CommandFactory {
    @Override
    public Command createCommand(ChannelSession channel, String command) throws IOException {

        // 解析 commandLine 字符串来决定创建哪个 Command
        // 例如，可以基于命令的第一个单词，或者使用更复杂的参数解析
        String[] parts = command.trim().split("\\s+", 2); // 按第一个空格分割
        String commandName = parts[0].toLowerCase(); // 命令名不区分大小写

        switch (commandName) {
            case "get_ssh_server_status":
                CheckAgentRunningStatusCommand checkAgentRunningStatusCommand = new CheckAgentRunningStatusCommand(command);
                // agent节点发送一次心跳
                boolean sendHearBeat = new HeartBeat().sendHearBeat();

                return checkAgentRunningStatusCommand;

            default:
                ShellFactory factory = new ProcessShellFactory(command, CommandFactory.split(command));
                return factory.createShell(channel);
        }
    }
}
