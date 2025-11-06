-- Extend incident_logs.event_type check to include OT events
ALTER TABLE incident_logs DROP CONSTRAINT IF EXISTS incident_logs_event_type_check;

ALTER TABLE incident_logs
  ADD CONSTRAINT incident_logs_event_type_check
  CHECK (event_type IN (
    'FAILED_LOGIN',
    'UNAUTHORIZED_ACCESS',
    'FILE_TAMPER',
    'INTEGRITY_MISMATCH',
    'DECRYPTION_DENIED',
    'LOGIN_SUCCESS',
    'ACCOUNT_LOCKED',
    'LOGOUT',
    'VALIDATION_FAILED',
    'FILE_UPLOAD_STORED',
    'FILE_UPLOAD_FAILED'
  ));