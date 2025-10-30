export interface Env {
  ASSETS?: Fetcher;

  DAYDROP_BUCKET: R2Bucket;
  DAYDROP_KV: KVNamespace;

  ACCOUNT_ID: string;
  BUCKET_NAME: string;

  TURNSTILE_SECRET_KEY: string;
  TURNSTILE_SITE_KEY: string;

  R2_ACCESS_KEY_ID: string;
  R2_SECRET_ACCESS_KEY: string;

  DEFAULT_TTL_SECONDS?: string;
  MAX_TOTAL_BYTES?: string;
}

export type EncryptionMeta =
  | null
  | { method: "AES-GCM"; saltB64: string; ivB64: string; iterations: number };

export interface FileRecord {
  code: string;
  objectKey: string;
  filename: string;
  contentType: string;
  size: number;
  createdAt: number;
  expiresAt: number;
  downloads: number;
  enc: EncryptionMeta;
}

/* 上传会话与请求体 */
export interface UploadMpuInitBody {
  filename: string;
  contentType: string;
  size: number;
  turnstileToken: string;
}
export interface UploadMpuInitResp {
  code: string;
  objectKey: string;
  uploadId: string;
  partSize: number;
  resumeUntil: number;
  auth: string;
}
export interface UploadMpuPresignBody {
  objectKey: string;
  uploadId: string;
  partNumbers: number[];
  estimatedSeconds: number;
  auth?: string;
  turnstileToken?: string;
}
export interface UploadMpuPresignResp {
  urls: { partNumber: number; url: string }[];
  expiresAt: number;
}
export interface UploadMpuCompleteBody {
  objectKey: string;
  uploadId: string;
  parts: { partNumber: number; etag: string }[];
  code: string;
  filename: string;
  contentType: string;
  size: number;
  enc: EncryptionMeta;
  auth?: string;
  turnstileToken?: string;
}
export interface UploadMpuAbortBody {
  objectKey: string;
  uploadId: string;
  auth?: string;
  turnstileToken?: string;
}

/* 下载会话与请求体 */
export interface DownloadUrlBody {
  code: string;
  estimatedSeconds: number;
  auth?: string;
  turnstileToken?: string;
}
export interface DownloadUrlResp {
  downloadUrl: string;
  meta: {
    filename: string;
    contentType: string;
    size: number;
    enc: EncryptionMeta;
    supportsRange: true;
  };
  expiresAt: number;
  auth?: string; // 首验后下发下载会话
}

/* ✅ 新增：仅检查是否存在 */
export interface CheckCodeBody {
  code: string;
  auth?: string;
  turnstileToken?: string;
}
export interface CheckCodeResp {
  ok: true;
  meta: {
    filename: string;
    contentType: string;
    size: number;
    enc: EncryptionMeta;
  };
  auth?: string; // 首验也可直接下发下载会话
}
