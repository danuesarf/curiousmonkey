-- Callers recorded as "role/undefined": a role session whose CloudTrail record had no session ARN (the target account's
-- copy of a cross-account AssumeRole) was named from the role's own ARN, which the name was not read from. All such
-- callers of a role in one account were stored as one. The name cannot be recovered from what was stored; they are
-- relabelled, and callers seen from now on get their role's name (an IAM Identity Center sign-in included).
UPDATE principals SET display = 'a role in ' || split_part(key, ':', 2) || ' (its name was not read: seen before a fix)'
 WHERE key LIKE 'role:%:undefined';
UPDATE changes SET detail = replace(detail, 'role/undefined (', 'a role (name not read) in (')
 WHERE kind = 'new-caller' AND detail LIKE 'role/undefined (%';
