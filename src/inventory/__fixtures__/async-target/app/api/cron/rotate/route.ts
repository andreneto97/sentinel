export const runtime = "edge";
export const maxDuration = 60;

/** Rotates API keys. Called by the Vercel cron, and it checks the shared secret. */
export async function GET(request: Request): Promise<Response> {
  const authorization = request.headers.get("authorization");
  if (authorization !== `Bearer ${process.env.CRON_SECRET}`) {
    return new Response("forbidden", { status: 403 });
  }
  await rotate();
  return new Response("rotated");
}

async function rotate(): Promise<void> {
  await fetch("https://api.example.test/internal/rotate", { method: "POST" });
}
