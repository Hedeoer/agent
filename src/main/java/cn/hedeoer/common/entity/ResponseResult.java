package cn.hedeoer.common.entity;

import cn.hedeoer.common.enmu.ResponseStatus;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Builder;
import lombok.Data;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

@Data
@Builder
public class ResponseResult<T> {

    /**
     * response timestamp.
     */
    private long timestamp;

    /**
     * response code, 200 -> OK.
     */
    private String status;

    /**
     * response message.
     */
    private String message;

    /**
     * response data.
     */
    private T data;

    /**
     * response success result wrapper.
     *
     * @param <T> type of data class
     * @return response result
     */
    public static <T> ResponseResult<T> success() {
        return success(null);
    }

    /**
     * response success result wrapper.
     *
     * @param data response data
     * @param <T>  type of data class
     * @return response result
     */
    public static <T> ResponseResult<T> success(T data) {
        return ResponseResult.<T>builder().data(data)
                .message(ResponseStatus.SUCCESS.getDescription())
                .status(ResponseStatus.SUCCESS.getResponseCode())
                .timestamp(System.currentTimeMillis())
                .build();
    }

    /**
     * response error result wrapper.
     *
     * @param message error message
     * @param <T>     type of data class
     * @return response result
     */
    public static <T extends Serializable> ResponseResult<T> fail(String message) {
        return fail(null, message);
    }

    /**
     * response error result wrapper.
     *
     * @param data    response data
     * @param message error message
     * @param <T>     type of data class
     * @return response result
     */
    public static <T> ResponseResult<T> fail(T data, String message) {
        return ResponseResult.<T>builder().data(data)
                .message(message)
                .status(ResponseStatus.FAIL.getResponseCode())
                .timestamp(System.currentTimeMillis())
                .build();
    }

    /**
     * 将ResponseResult对象转换为Map<String, String>
     * @param responseResult 需要转换的ResponseResult对象
     * @param <T> 数据类型
     * @return 转换后的Map
     */
    public static <T> Map<String, String> convertResponseResultToMap(ResponseResult<T> responseResult) {
        if (responseResult == null) {
            return new HashMap<>();
        }

        Map<String, String> resultMap = new HashMap<>();

        // 添加timestamp字段
        resultMap.put("timestamp", String.valueOf(responseResult.getTimestamp()));

        // 添加status字段
        if (responseResult.getStatus() != null) {
            resultMap.put("status", responseResult.getStatus());
        }

        // 添加message字段
        if (responseResult.getMessage() != null) {
            resultMap.put("message", responseResult.getMessage());
        }

        // 处理data字段
        T data = responseResult.getData();
        if (data != null) {
            String dataStr;

            // 如果data是集合类型
            if (data instanceof Collection) {
                ObjectMapper objectMapper = new ObjectMapper();
                try {
                    // todo use jackson to covert collector
                    dataStr = objectMapper.writeValueAsString(data);
                } catch (JsonProcessingException e) {
                    throw new RuntimeException(e);
                }
                /*Collection<?> collection = (Collection<?>) data;
                StringBuilder sb = new StringBuilder("[");
                boolean first = true;

                for (Object item : collection) {
                    if (!first) {
                        sb.append(", ");
                    }
                    sb.append(item.toString());
                    first = false;
                }

                sb.append("]");
                dataStr = sb.toString();*/
            }
            // 如果data是Map类型
            else if (data instanceof Map) {
                Map<?, ?> map = (Map<?, ?>) data;
                StringBuilder sb = new StringBuilder("{");
                boolean first = true;

                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    if (!first) {
                        sb.append(", ");
                    }
                    sb.append(entry.getKey()).append("=").append(entry.getValue());
                    first = false;
                }

                sb.append("}");
                dataStr = sb.toString();
            }
            // 其他类型直接使用toString()
            else {
                dataStr = data.toString();
            }

            resultMap.put("data", dataStr);
        }

        return resultMap;
    }


}