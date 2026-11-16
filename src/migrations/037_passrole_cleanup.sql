-- PassRole used to be inferred from any role ARN in a request, so roles that only read or analyzed other roles
-- (iam:GetRole, iam:GenerateServiceLastAccessedDetails, Access Analyzer policy generation and validation) showed as
-- having passed them. IAM and STS never take a passed role, so those rows are all wrong. Access Analyzer's only real
-- pass is the CloudTrail access role of StartPolicyGeneration; the stored rows cannot tell it apart from the analyzed
-- principal, so they go too and a real one comes back on the next scan that sees it.
DELETE FROM passrole_observed WHERE service IN ('iam', 'sts', 'access-analyzer');
