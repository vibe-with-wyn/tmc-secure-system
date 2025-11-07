package com.tmc.system.tmc_secure_system.util;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

/**
 * Small helpers to parse date inputs consistently.
 */
public final class DateRanges {
    private DateRanges(){}

    public static LocalDateTime parseStart(String s) {
        if (s == null || s.isBlank()) return null;
        LocalDate d = LocalDate.parse(s, DateTimeFormatter.ISO_DATE);
        return d.atStartOfDay();
    }

    public static LocalDateTime parseEnd(String s) {
        if (s == null || s.isBlank()) return null;
        LocalDate d = LocalDate.parse(s, DateTimeFormatter.ISO_DATE);
        return d.atTime(LocalTime.MAX);
    }
}