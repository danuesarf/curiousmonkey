// Permissions that Event History (management events only) cannot confirm. These are never called "unused".
import { globMatch } from './wildcard.js';

// Data-plane actions. They are only in CloudTrail when data events are enabled for that resource type.
const DATA_EVENT = [
  's3:GetObject*', 's3:PutObject*', 's3:DeleteObject*', 's3:AbortMultipartUpload', 's3:ListMultipartUploadParts',
  's3:RestoreObject', 's3:ReplicateObject', 's3:GetObjectAttributes',
  'dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem', 'dynamodb:DeleteItem', 'dynamodb:Query', 'dynamodb:Scan',
  'dynamodb:BatchGetItem', 'dynamodb:BatchWriteItem', 'dynamodb:ConditionCheckItem', 'dynamodb:PartiQL*',
  'lambda:InvokeFunction', 'lambda:InvokeAsync',
  'sns:Publish', 'kinesis:PutRecord*', 'kinesis:GetRecords',
];
// CloudTrail has no data-event type for these at all, so no setting can ever confirm them.
const NEVER_LOGGED = ['sqs:SendMessage*', 'sqs:ReceiveMessage', 'sqs:DeleteMessage*', 'sqs:ChangeMessageVisibility*'];
// Checked by AWS but never written to CloudTrail as their own event.
const AUTHORIZATION_ONLY = ['iam:PassRole', 'sts:TagSession', 'sts:SetSourceIdentity'];

export const dataEventResource = (action) => {
  const svc = action.split(':')[0].toLowerCase();
  return { s3: 'AWS::S3::Object', dynamodb: 'AWS::DynamoDB::Table', lambda: 'AWS::Lambda::Function',
    sns: 'AWS::SNS::Topic', kinesis: 'AWS::Kinesis::Stream' }[svc] || null;
};

export function unloggableReason(action) {
  if (AUTHORIZATION_ONLY.some((p) => globMatch(p, action, { ci: true }))) return 'authorization-only';
  if (NEVER_LOGGED.some((p) => globMatch(p, action, { ci: true }))) return 'not-logged';
  if (DATA_EVENT.some((p) => globMatch(p, action, { ci: true }))) return 'data-event';
  return null;
}
