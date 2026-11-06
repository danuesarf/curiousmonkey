// CloudTrail names an API call by eventSource + eventName. IAM names the permission differently in a few places.
import { canonicalAction, actionInfo } from './catalog.js';

const PREFIX = {
  monitoring: 'cloudwatch', email: 'ses', tagging: 'tag', 'sso-directory': 'sso-directory',
  'runtime.sagemaker': 'sagemaker', 'api.ecr': 'ecr', 'kinesisanalytics': 'kinesisanalytics',
};
const S3_ALIAS = {
  ListBuckets: 's3:ListAllMyBuckets', HeadBucket: 's3:ListBucket', ListObjects: 's3:ListBucket',
  ListObjectsV2: 's3:ListBucket', ListObjectVersions: 's3:ListBucketVersions', HeadObject: 's3:GetObject',
  GetBucketLocation: 's3:GetBucketLocation', CreateMultipartUpload: 's3:PutObject', UploadPart: 's3:PutObject',
  CompleteMultipartUpload: 's3:PutObject', ListMultipartUploads: 's3:ListBucketMultipartUploads',
  ListParts: 's3:ListMultipartUploadParts', DeleteObjects: 's3:DeleteObject', CopyObject: 's3:PutObject',
};
const APIGW_VERB = [['Get', 'GET'], ['Create', 'POST'], ['Put', 'PUT'], ['Update', 'PATCH'], ['Delete', 'DELETE'], ['Import', 'PUT'], ['Test', 'POST']];

export function eventToAction(eventSource, eventName) {
  if (!eventSource || !eventName) return null;
  let svc = eventSource.replace(/\.amazonaws\.com(\.cn)?$/, '');
  svc = PREFIX[svc] || svc;
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
