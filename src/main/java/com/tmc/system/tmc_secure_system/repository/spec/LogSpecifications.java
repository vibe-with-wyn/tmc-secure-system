package com.tmc.system.tmc_secure_system.repository.spec;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import org.springframework.data.jpa.domain.Specification;

import com.tmc.system.tmc_secure_system.entity.AuditLog;
import com.tmc.system.tmc_secure_system.entity.IncidentLog;
import com.tmc.system.tmc_secure_system.entity.enums.IncidentSeverity;

import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Predicate;

/**
 * Shared Specifications to keep controllers clean and avoid null-param SQL.
 */
public final class LogSpecifications {
    private LogSpecifications(){}

    public static Specification<IncidentLog> forIncidents(Long actorId,
                                                          IncidentSeverity severity,
                                                          LocalDateTime from,
                                                          LocalDateTime to) {
        return (root, query, cb) -> {
            List<Predicate> ps = new ArrayList<>();
            if (actorId != null) {
                Join<Object, Object> actor = root.join("actor", JoinType.LEFT);
                ps.add(cb.equal(actor.get("id"), actorId));
            }
            if (severity != null) {
                ps.add(cb.equal(root.get("severity"), severity));
            }
            if (from != null) ps.add(cb.greaterThanOrEqualTo(root.get("eventTime"), from));
            if (to != null) ps.add(cb.lessThanOrEqualTo(root.get("eventTime"), to));
            query.orderBy(cb.desc(root.get("eventTime")));
            return cb.and(ps.toArray(new Predicate[0]));
        };
    }

    public static Specification<AuditLog> forAudits(Long actorId,
                                                    LocalDateTime from,
                                                    LocalDateTime to) {
        return (root, query, cb) -> {
            List<Predicate> ps = new ArrayList<>();
            if (actorId != null) {
                Join<Object, Object> actor = root.join("actor", JoinType.LEFT);
                ps.add(cb.equal(actor.get("id"), actorId));
            }
            if (from != null) ps.add(cb.greaterThanOrEqualTo(root.get("eventTime"), from));
            if (to != null) ps.add(cb.lessThanOrEqualTo(root.get("eventTime"), to));
            query.orderBy(cb.desc(root.get("eventTime")));
            return cb.and(ps.toArray(new Predicate[0]));
        };
    }
}