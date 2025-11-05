package com.tmc.system.tmc_secure_system.util.excel;

import java.io.InputStream;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

public class ExcelValidator {

    // Timestamp | MachineID | Temperature (°C) | Pressure (bar) | Vibration (Hz) |
    // OutputRate (units/hr) | EnergyConsumption (kWh) | OperatorID | Status
    private static final Set<String> REQUIRED_HEADERS_CANONICAL = Set.of(
        "timestamp",
        "machineid",
        "temperaturec",
        "pressurebar",
        "vibrationhz",
        "outputrateunitshr",
        "energyconsumptionkwh",
        "operatorid",
        "status"
    );

    // Friendly names for error messages (ordered)
    private static final List<String> REQUIRED_HEADERS_FRIENDLY = List.of(
        "Timestamp",
        "MachineID",
        "Temperature (°C)",
        "Pressure (bar)",
        "Vibration (Hz)",
        "OutputRate (units/hr)",
        "EnergyConsumption (kWh)",
        "OperatorID",
        "Status"
    );

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
                    if (raw != null) {
                        headersCanonical.add(canonicalize(raw));
                    }
                }
            }

            // Determine missing headers by canonical comparison
            List<String> missing = REQUIRED_HEADERS_CANONICAL.stream()
                .filter(req -> !headersCanonical.contains(req))
                .map(ExcelValidator::toFriendlyFromCanonical)
                .collect(Collectors.toList());

            if (!missing.isEmpty()) {
                String msg = "Missing required headers: " + String.join(", ", missing);
                return new ValidationResult(false, msg, missing);
            }

            // Basic data presence check: at least one data row
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
        // Map canonical back to friendly label if we know it; else return canonical
        int idx = List.of(
            "timestamp",
            "machineid",
            "temperaturec",
            "pressurebar",
            "vibrationhz",
            "outputrateunitshr",
            "energyconsumptionkwh",
            "operatorid",
            "status"
        ).indexOf(c);
        if (idx >= 0 && idx < REQUIRED_HEADERS_FRIENDLY.size()) {
            return REQUIRED_HEADERS_FRIENDLY.get(idx);
        }
        return c;
    }

    public record ValidationResult(boolean valid, String message, List<String> errors) {
        public static ValidationResult ok(String message) {
            return new ValidationResult(true, message, List.of());
        }
        public static ValidationResult fail(String message) {
            return new ValidationResult(false, message, List.of(message));
        }
    }
}