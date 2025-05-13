package cn.hedeoer.util;

import lombok.extern.slf4j.Slf4j;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class YamlUtil {

    // 配置文件名字
    private static final String CONFIG_FILE_NAME = "application.yaml";

    /**
     * 获取yaml文件中某个顶级节点下的所有配置
     * @param topNodeName yaml某个顶级节点的名字
     * @return Map<String, Object>
     */
    public static Map<String, Object> getYamlConfig(String topNodeName) {
        try (InputStream inputStream = YamlUtil.class.getClassLoader().getResourceAsStream(CONFIG_FILE_NAME)) {
            Map<String, Object> config = new HashMap<>();

            Yaml yaml = new Yaml();

            if (inputStream == null) {
                log.error("{} not found in classpath. {} cannot be configured.", CONFIG_FILE_NAME,topNodeName);
                return config; // 中断加载
            }

            Map<String, Object> loadedYaml = yaml.load(inputStream);

            if (loadedYaml == null || !(loadedYaml.get(topNodeName) instanceof Map)) {
                log.error("'{}' is missing '{}' root key or it's not a map.", CONFIG_FILE_NAME,topNodeName);
                return config; // 中断加载
            }

            config = (Map<String, Object>) loadedYaml.get(topNodeName);
            return config;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
