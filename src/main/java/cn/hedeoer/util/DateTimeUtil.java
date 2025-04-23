package cn.hedeoer.util;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

public class DateTimeUtil {

    /**
     * Converts a date-time string in ISO 8601 format to a LocalDateTime.
     * 
     * @param dateTimeString the date-time string to be converted (e.g., "2024-12-19T05:01:55Z")
     * @return the converted LocalDateTime
     * @throws IllegalArgumentException if the input string cannot be parsed
     */
    public static LocalDateTime parseToLocalDateTime(String dateTimeString) {
        if (dateTimeString == null || dateTimeString.isEmpty()) {
            throw new IllegalArgumentException("Input dateTimeString cannot be null or empty");
        }

        try {
            // Parse the input string using ISO_DATE_TIME formatter
            return LocalDateTime.parse(dateTimeString, DateTimeFormatter.ISO_DATE_TIME);
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException("Invalid dateTimeString format: " + dateTimeString, e);
        }
    }

    /**
     * Converts a date-time string in a custom format (e.g., "yyyy-MM-dd HH:mm:ss") to a LocalDateTime.
     *
     * @param dateTimeString the date-time string to be converted (e.g., "2024-12-26 22:12:18")
     * @param pattern        the custom date-time pattern to parse the input string
     * @return the converted LocalDateTime
     * @throws IllegalArgumentException if the input string cannot be parsed
     */
    public static LocalDateTime parseToLocalDateTime(String dateTimeString, String pattern) {
        if (dateTimeString == null || dateTimeString.isEmpty()) {
            throw new IllegalArgumentException("Input dateTimeString cannot be null or empty");
        }
        if (pattern == null || pattern.isEmpty()) {
            throw new IllegalArgumentException("Pattern cannot be null or empty");
        }

        try {
            // Parse the input string using the provided custom formatter
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern(pattern);
            return LocalDateTime.parse(dateTimeString, formatter);
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException("Invalid dateTimeString format or pattern: " + dateTimeString, e);
        }
    }

    /**
     *  秒级时间戳转化为 yyyy-MM-dd HH:mm:ss格式日期时间字符串
     *  时区为系统默认时区
     * @param timestampSec
     * @return
     */
    public static String timestampSecToString(long timestampSec) {
        LocalDateTime dateTime = LocalDateTime.ofInstant(
                Instant.ofEpochSecond(timestampSec),
                ZoneId.systemDefault()
        );
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        return dateTime.format(formatter);
    }

    public static void main(String[] args) {
        // Example usage
        String dateTimeStringISO = "2024-12-19T05:01:55";
        String dateTimeStringCustom = "2024-12-26 22:12:18";

        // ISO format parsing
        LocalDateTime dateTime1 = parseToLocalDateTime(dateTimeStringISO);
        System.out.println("Parsed ISO date-time: " + dateTime1);

        // Custom format parsing
        LocalDateTime dateTime2 = parseToLocalDateTime(dateTimeStringCustom, "yyyy-MM-dd HH:mm:ss");
        System.out.println("Parsed custom date-time: " + dateTime2);
    }
}
