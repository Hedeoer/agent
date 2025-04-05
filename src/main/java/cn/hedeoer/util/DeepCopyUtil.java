package cn.hedeoer.util;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * 深拷贝工具类
 * 1.类需要有无参构造函数：被拷贝的类需要有默认(无参)构造函数
 * 2. 使用方法
 * PortRule copy = DeepCopyUtil.deepCopy(original, PortRule.class);
 * List<PortRule> copyList = DeepCopyUtil.deepCopy(origList,
 *                           new TypeReference<List<PortRule>>(){});
 *
 *
 */
public class DeepCopyUtil {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    
    static {
        // 配置ObjectMapper
        MAPPER.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }
    
    public static <T> T deepCopy(T original, Class<T> clazz) {
        try {
            String json = MAPPER.writeValueAsString(original);
            return MAPPER.readValue(json, clazz);
        } catch (Exception e) {
            throw new RuntimeException("Failed to deep copy object", e);
        }
    }
    
    public static <T> T deepCopy(T original, TypeReference<T> typeReference) {
        try {
            String json = MAPPER.writeValueAsString(original);
            return MAPPER.readValue(json, typeReference);
        } catch (Exception e) {
            throw new RuntimeException("Failed to deep copy object", e);
        }
    }
}