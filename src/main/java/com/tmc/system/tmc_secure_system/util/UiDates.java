package com.tmc.system.tmc_secure_system.util;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import org.springframework.stereotype.Component;

/**
 * UI-friendly date/time formatter. Use in Thymeleaf via: ${@uiDates.format(dt)}
 */
@Component("uiDates")
public class UiDates {
    // ISO-like but human friendly
    private static final DateTimeFormatter UI = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public String format(LocalDateTime dt) {
        return dt == null ? "" : UI.format(dt);
    }

    public String pattern() {
        return "yyyy-MM-dd HH:mm:ss";
    }
}