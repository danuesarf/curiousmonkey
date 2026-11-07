// CloudTrail names an API call by eventSource + eventName. IAM names the permission differently in a few places.
import { canonicalAction, actionInfo } from './catalog.js';

const PREFIX = {
  monitoring: 'cloudwatch', email: 'ses', tagging: 'tag', 'sso-directory': 'sso-directory',
  'runtime.sagemaker': 'sagemaker', 'api.ecr': 'ecr', 'kinesisanalytics': 'kinesisanalytics',
  cloudcontrolapi: 'cloudformation',     // Cloud Control API's permissions use the cloudformation prefix
  pinpoint: 'mobiletargeting',           // Amazon Pinpoint's permissions use mobiletargeting
};
const S3_ALIAS = {
  ListBuckets: 's3:ListAllMyBuckets', HeadBucket: 's3:ListBucket', ListObjects: 's3:ListBucket',
  ListObjectsV2: 's3:ListBucket', ListObjectVersions: 's3:ListBucketVersions', HeadObject: 's3:GetObject',
  GetBucketLocation: 's3:GetBucketLocation', CreateMultipartUpload: 's3:PutObject', UploadPart: 's3:PutObject',
  CompleteMultipartUpload: 's3:PutObject', ListMultipartUploads: 's3:ListBucketMultipartUploads',
  ListParts: 's3:ListMultipartUploadParts', DeleteObjects: 's3:DeleteObject', CopyObject: 's3:PutObject',
  UploadPartCopy: 's3:PutObject', SelectObjectContent: 's3:GetObject',
  // bucket configuration: the event says Bucket…, the permission says …Configuration
  GetBucketEncryption: 's3:GetEncryptionConfiguration', PutBucketEncryption: 's3:PutEncryptionConfiguration', DeleteBucketEncryption: 's3:PutEncryptionConfiguration',
  GetBucketLifecycle: 's3:GetLifecycleConfiguration', GetBucketLifecycleConfiguration: 's3:GetLifecycleConfiguration',
  PutBucketLifecycle: 's3:PutLifecycleConfiguration', PutBucketLifecycleConfiguration: 's3:PutLifecycleConfiguration', DeleteBucketLifecycle: 's3:PutLifecycleConfiguration',
  GetBucketReplication: 's3:GetReplicationConfiguration', PutBucketReplication: 's3:PutReplicationConfiguration', DeleteBucketReplication: 's3:PutReplicationConfiguration',
  GetBucketCors: 's3:GetBucketCORS', PutBucketCors: 's3:PutBucketCORS', DeleteBucketCors: 's3:PutBucketCORS',
  GetBucketAccelerateConfiguration: 's3:GetAccelerateConfiguration', PutBucketAccelerateConfiguration: 's3:PutAccelerateConfiguration',
  GetBucketIntelligentTieringConfiguration: 's3:GetIntelligentTieringConfiguration', ListBucketIntelligentTieringConfigurations: 's3:GetIntelligentTieringConfiguration',
  PutBucketIntelligentTieringConfiguration: 's3:PutIntelligentTieringConfiguration', DeleteBucketIntelligentTieringConfiguration: 's3:PutIntelligentTieringConfiguration',
  GetBucketAnalyticsConfiguration: 's3:GetAnalyticsConfiguration', ListBucketAnalyticsConfigurations: 's3:GetAnalyticsConfiguration',
  PutBucketAnalyticsConfiguration: 's3:PutAnalyticsConfiguration', DeleteBucketAnalyticsConfiguration: 's3:PutAnalyticsConfiguration',
  GetBucketInventoryConfiguration: 's3:GetInventoryConfiguration', ListBucketInventoryConfigurations: 's3:GetInventoryConfiguration',
  PutBucketInventoryConfiguration: 's3:PutInventoryConfiguration', DeleteBucketInventoryConfiguration: 's3:PutInventoryConfiguration',
  GetBucketMetricsConfiguration: 's3:GetMetricsConfiguration', ListBucketMetricsConfigurations: 's3:GetMetricsConfiguration',
  PutBucketMetricsConfiguration: 's3:PutMetricsConfiguration', DeleteBucketMetricsConfiguration: 's3:PutMetricsConfiguration',
  GetBucketNotificationConfiguration: 's3:GetBucketNotification', PutBucketNotificationConfiguration: 's3:PutBucketNotification',
  GetObjectLockConfiguration: 's3:GetBucketObjectLockConfiguration', PutObjectLockConfiguration: 's3:PutBucketObjectLockConfiguration',
  GetPublicAccessBlock: 's3:GetBucketPublicAccessBlock', PutPublicAccessBlock: 's3:PutBucketPublicAccessBlock', DeletePublicAccessBlock: 's3:PutBucketPublicAccessBlock',
  DeleteBucketTagging: 's3:PutBucketTagging', DeleteBucketOwnershipControls: 's3:PutBucketOwnershipControls',
  ListDirectoryBuckets: 's3express:ListAllMyDirectoryBuckets',
};
// one event source, two services: Application Auto Scaling logs as autoscaling.amazonaws.com too.
// Only names that EC2 Auto Scaling does not also have are moved; the shared ones stay ambiguous.
const APP_AUTOSCALING = new Set(['DescribeScalableTargets', 'RegisterScalableTarget', 'DeregisterScalableTarget', 'DescribeScalingPolicies', 'DeleteScalingPolicy',
  'PutScheduledAction', 'GetPredictiveScalingForecast', 'TagResource', 'UntagResource', 'ListTagsForResource']);
const EVENT_ALIAS = { 's3express:ListDirectoryBuckets': 's3express:ListAllMyDirectoryBuckets' };
const APIGW_VERB = [['Get', 'GET'], ['Create', 'POST'], ['Put', 'PUT'], ['Update', 'PATCH'], ['Delete', 'DELETE'], ['Import', 'PUT'], ['Test', 'POST']];

export function eventToAction(eventSource, eventName) {
  if (!eventSource || !eventName) return null;
  let svc = eventSource.replace(/\.amazonaws\.com(\.cn)?$/, '');
  svc = PREFIX[svc] || svc;
  if (EVENT_ALIAS[`${svc}:${eventName}`]) return canonicalAction(EVENT_ALIAS[`${svc}:${eventName}`]);
  if (svc === 'autoscaling' && APP_AUTOSCALING.has(eventName)) return canonicalAction(`application-autoscaling:${eventName}`);
  if (svc === 'mediapackage' && /Packaging|Asset/.test(eventName)) return canonicalAction(`mediapackage-vod:${eventName}`);   // MediaPackage VOD
  if (svc === 's3') return canonicalAction(S3_ALIAS[eventName] || `s3:${eventName}`);
  if (svc === 'lambda') return canonicalAction(`lambda:${eventName.replace(/\d{8}.*$/, '')}`); // GetFunction20150331v2
  if (svc === 'apigateway') {
    const v = APIGW_VERB.find(([p]) => eventName.startsWith(p));
    return v ? `apigateway:${v[1]}` : null;
  }
  if (svc === 'sts' && /^AssumeRole/.test(eventName)) return canonicalAction(`sts:${eventName}`);
  return canonicalAction(`${svc}:${eventName}`);
}

export const isKnownAction = (a) => Boolean(actionInfo(a));
export const isDenied = (errorCode) => /AccessDenied|UnauthorizedOperation|UnauthorizedAccess|Unauthorized|Forbidden/i.test(errorCode || '');

// Sign-in events are logged against roles but check no IAM permission.
const NO_PERMISSION_SOURCES = new Set(['signin.amazonaws.com']);
const VERSION_SUFFIX = /(\d{4}_\d{2}_\d{2}|\d{8})(v\d+)?$/;   // GetDistribution2020_05_31, ListFunctions20150331v2

/**
 * Map one CloudTrail event to the IAM action it was authorised as.
 *   { action, mapped: true }          a known IAM action
 *   { action: null, none: true }      no permission involved (console sign-in)
 *   { action: 'svc:Name', mapped: false }  not in the catalog. The raw key is kept so a mapping
 *                                     (manual or Bedrock) can credit it later without a rescan.
 */
export function mapEvent(eventSource, eventName) {
  if (!eventSource || !eventName) return { action: null, mapped: false };
  if (NO_PERMISSION_SOURCES.has(eventSource)) return { action: null, mapped: true, none: true };
  const direct = eventToAction(eventSource, eventName);
  if (direct && isKnownAction(direct)) return { action: direct, mapped: true };
  const base = eventName.replace(VERSION_SUFFIX, '');
  if (base && base !== eventName) {
    const a = eventToAction(eventSource, base);
    if (a && isKnownAction(a)) return { action: a, mapped: true };
  }
  return { action: direct, mapped: false };
}
