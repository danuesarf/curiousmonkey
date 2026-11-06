// Generates the read-only scanner role an account owner deploys. Explicit Deny on data reads means a
// stolen scanner credential still cannot read customer data, even if someone later widens the Allow.
import { config } from './config.js';

export const SCANNER_ALLOW = [
  'iam:ListRoles', 'iam:GetRole', 'iam:ListRolePolicies', 'iam:GetRolePolicy', 'iam:ListAttachedRolePolicies', 'iam:GetPolicy', 'iam:GetPolicyVersion',
  'iam:GenerateServiceLastAccessedDetails', 'iam:GetServiceLastAccessedDetails', 'cloudtrail:LookupEvents', 'cloudtrail:DescribeTrails',
  'cloudtrail:GetEventSelectors', 'cloudtrail:ListEventDataStores', 'organizations:DescribeOrganization',
];
export const SCANNER_DENY = [
  's3:GetObject', 's3:GetObjectVersion', 'dynamodb:GetItem', 'dynamodb:BatchGetItem', 'dynamodb:Query', 'dynamodb:Scan', 'secretsmanager:GetSecretValue',
  'kms:Decrypt', 'ssm:GetParameter', 'ssm:GetParameters', 'ssm:GetParametersByPath', 'sqs:ReceiveMessage', 'lambda:InvokeFunction',
];

export function scannerSnippets({ principalArn, roleName, externalId }) {
  const trust = { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { AWS: principalArn || 'arn:aws:iam::<YOUR_SCANNER_ACCOUNT>:role/<WORKER_ROLE>' },
    Action: 'sts:AssumeRole', Condition: { StringEquals: { 'sts:ExternalId': externalId } } }] };
  const perms = { Version: '2012-10-17', Statement: [
    { Sid: 'ReadIamAndTrailMetadata', Effect: 'Allow', Action: SCANNER_ALLOW, Resource: '*' },
    { Sid: 'NeverReadCustomerData', Effect: 'Deny', Action: SCANNER_DENY, Resource: '*' }] };
  const terraform = `resource "aws_iam_role" "curious_monkey" {
  name               = "${roleName}"
  assume_role_policy = jsonencode(${JSON.stringify(trust, null, 2).replace(/\n/g, '\n  ')})
}

resource "aws_iam_role_policy" "curious_monkey" {
  name   = "curious-monkey-read-only"
  role   = aws_iam_role.curious_monkey.id
  policy = jsonencode(${JSON.stringify(perms, null, 2).replace(/\n/g, '\n  ')})
}`;
  const cloudformation = `AWSTemplateFormatVersion: '2010-09-09'
Description: Curious Monkey read-only scanner role
Resources:
  CuriousMonkeyScanner:
    Type: AWS::IAM::Role
    Properties:
      RoleName: ${roleName}
      AssumeRolePolicyDocument: ${JSON.stringify(trust)}
      Policies:
        - PolicyName: curious-monkey-read-only
          PolicyDocument: ${JSON.stringify(perms)}
Outputs:
  RoleArn:
    Value: !GetAtt CuriousMonkeyScanner.Arn`;
  return { trust, perms, terraform, cloudformation };
}
export const defaultRoleName = () => config.scanner.roleName;
