package com.tmc.system.tmc_secure_system.util.excel;

import java.io.InputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

public class ExcelValidator {

    // Define required headers once with canonical+friendly names
    private static final List<HeaderSpec> REQUIRED = List.of(
        new HeaderSpec("timestamp", "Timestamp"),
        new HeaderSpec("machineid", "MachineID"),
        new HeaderSpec("temperaturec", "Temperature (°C)"),
        new HeaderSpec("pressurebar", "Pressure (bar)"),
        new HeaderSpec("vibrationhz", "Vibration (Hz)"),
        new HeaderSpec("outputrateunitshr", "OutputRate (units/hr)"),
        new HeaderSpec("energyconsumptionkwh", "EnergyConsumption (kWh)"),
        new HeaderSpec("operatorid", "OperatorID"),
        new HeaderSpec("status", "Status")
    );

    private static final Set<String> REQUIRED_CANONICAL = REQUIRED.stream()
            .map(HeaderSpec::canonical).collect(Collectors.toUnmodifiableSet());

    private static final Map<String, String> CANONICAL_TO_FRIENDLY = buildFriendlyMap();

    public static ValidationResult validate(InputStream in) {
        try (XSSFWorkbook wb = new XSSFWorkbook(in)) {
            if (wb.getNumberOfSheets() == 0) {
                return ValidationResult.fail("Workbook has no sheets");
            }
            Sheet sheet = wb.getSheetAt(0);
            Row header = sheet.getRow(0);
            if (header == null) {
                return ValidationResult.fail("Missing header row");
            }

            DataFormatter formatter = new DataFormatter();
            Set<String> headersCanonical = new HashSet<>();
            for (int i = 0; i < header.getLastCellNum(); i++) {
                Cell cell = header.getCell(i);
                if (cell != null) {
                    String raw = formatter.formatCellValue(cell);
                    if (raw != null) headersCanonical.add(canonicalize(raw));
                }
            }

            // Missing required headers
            List<String> missing = REQUIRED_CANONICAL.stream()
                .filter(req -> !headersCanonical.contains(req))
                .map(ExcelValidator::toFriendlyFromCanonical)
                .collect(Collectors.toList());

            if (!missing.isEmpty()) {
                String msg = "Missing required headers: " + String.join(", ", missing);
                return new ValidationResult(false, msg, missing);
            }

            // At least one data row
            if (sheet.getPhysicalNumberOfRows() < 2) {
                return ValidationResult.fail("No data rows found");
            }

            return ValidationResult.ok("Excel file validated successfully");
        } catch (Exception ex) {
            return ValidationResult.fail("Validation error: " + ex.getMessage());
        }
    }

    // Normalize header strings: lowercase, strip non-alphanumeric chars
    private static String canonicalize(String s) {
        return s.trim().toLowerCase().replaceAll("[^a-z0-9]", "");
    }

    private static String toFriendlyFromCanonical(String c) {
        return CANONICAL_TO_FRIENDLY.getOrDefault(c, c);
    }

    private static Map<String, String> buildFriendlyMap() {
        Map<String, String> m = new HashMap<>();
        for (HeaderSpec h : REQUIRED) m.put(h.canonical(), h.friendly());
        return m;
    }

    private record HeaderSpec(String canonical, String friendly) {}

    public record ValidationResult(boolean valid, String message, List<String> errors) {
        public static ValidationResult ok(String message) {
            return new ValidationResult(true, message, List.of());
        }
        public static ValidationResult fail(String message) {
            return new ValidationResult(false, message, List.of(message));
        }
    }
}