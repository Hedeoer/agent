package cn.hedeoer.util;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Properties;
import java.util.UUID;

public class AgentIdUtil {
    private static final char[] BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".toCharArray();
    private static final int AGENT_ID_LENGTH = 22;
    private static final String DEFAULT_PATH = "./agent.properties";

    /**
     * 加载或生成唯一 agentId。
     * <p>
     * 本方法首先尝试从本地持久化文件（如 ./agent.properties）中读取 agentId 字段。如果配置文件已存在并且 agentId 字段有效，
     *  (agentId不为空且长度必须为22位)
     * 则直接返回该唯一ID；若文件不存在或 agentId 字段缺失/为空，则自动生成一个新的 base62 压缩 UUID（长度22位，极高唯一性），
     * 并持久化写入文件，供下次或重启时复用。
     * <p>
     * 该方法可确保即使多次重启、异常退出，也能最大概率保证同一台机器/节点只有一个不变的唯一 agentId，适于集群注册与心跳场景。
     *
     * @return 本地唯一 agentId 字符串（22位 base62 编码，极高唯一性，持久化保证本机稳定不变）
     * @throws RuntimeException 文件读写异常（如没有权限或磁盘损坏等导致无法持久化 agentId）
     */
    public static String loadOrCreateUUID() {
        File file = new File(DEFAULT_PATH);
        Properties props = new Properties();
        String agentId;

        if (file.exists()) {
            try (FileReader reader = new FileReader(file)) {
                props.load(reader);
                agentId = props.getProperty("agentId");
                if (agentId == null || agentId.isBlank() || agentId.length() != 22) {
                    agentId = createNewAgentIdAndWrite(file);
                }
            } catch (IOException e) {
                throw new RuntimeException("读取 agent UUID 文件失败", e);
            }
        } else {
            agentId = createNewAgentIdAndWrite( file);
        }
        return agentId;
    }

    /**
     * 生成新的 agentId 并覆盖写入到指定文件（Properties格式），
     * 旧内容无论多少全部覆盖。
     *
     * @param file 持久化文件
     * @return 新生成的 agentId
     */
    private static String createNewAgentIdAndWrite(File file) {
        String uuid = newBase62Uuid();
        Properties props = new Properties();
        props.setProperty("agentId", uuid);
        try (FileWriter fw = new FileWriter(file, false)) { // false=覆盖
            props.store(fw, null); // 不添加注释行
        } catch (IOException e) {
            throw new RuntimeException("写入 agent UUID 文件失败", e);
        }
        return uuid;
    }

    /**
     * 生成固定22位长度的base62 UUID字符串（无负号安全）
     */
    private static String newBase62Uuid() {
        UUID uuid = UUID.randomUUID();
        byte[] bytes = new byte[16];
        ByteBuffer.wrap(bytes).putLong(uuid.getMostSignificantBits()).putLong(uuid.getLeastSignificantBits());
        BigInteger big = new BigInteger(1, bytes);
        // 转base62
        StringBuilder sb = new StringBuilder();
        BigInteger base = BigInteger.valueOf(62);
        do {
            BigInteger[] divmod = big.divideAndRemainder(base);
            sb.insert(0, BASE62[divmod[1].intValue()]);
            big = divmod[0];
        } while (big.compareTo(BigInteger.ZERO) > 0);
        // 补全长度
        while (sb.length() < AGENT_ID_LENGTH) {
            sb.insert(0, '0');
        }
        return sb.toString();
    }

    // demo
    public static void main(String[] args) {
        String agentId = loadOrCreateUUID();
        System.out.println("唯一 agentId: " + agentId + " 长度=" + agentId.length());
    }
}