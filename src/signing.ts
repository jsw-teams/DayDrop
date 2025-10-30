import { AwsClient } from "aws4fetch";
import type { Env } from "./types";

// 改为 path-style：https://{ACCOUNT_ID}.r2.cloudflarestorage.com/{BUCKET}/{key}
export function r2S3Base(env: Env) {
  return `https://${env.ACCOUNT_ID}.r2.cloudflarestorage.com/${env.BUCKET_NAME}`;
}

export function awsClient(env: Env) {
  return new AwsClient({
    accessKeyId: env.R2_ACCESS_KEY_ID,
    secretAccessKey: env.R2_SECRET_ACCESS_KEY,
    service: "s3",
    region: "auto"
  });
}

export async function presignUrl(
  env: Env,
  method: "PUT" | "GET" | "HEAD" | "DELETE",
  key: string,
  expiresSeconds: number,
  extraQuery?: Record<string, string | number>
): Promise<URL> {
  const base = new URL(r2S3Base(env));
  base.pathname = `/${env.BUCKET_NAME}/${key}`.replace(`/${env.BUCKET_NAME}/${env.BUCKET_NAME}/`, `/${env.BUCKET_NAME}/`); // 容错
  if (extraQuery) for (const [k, v] of Object.entries(extraQuery)) base.searchParams.set(k, String(v));
  base.searchParams.set("X-Amz-Expires", String(expiresSeconds));

  const client = awsClient(env);
  const signed = await client.sign(new Request(base, { method }), { aws: { signQuery: true } });
  return new URL(signed.url);
}
