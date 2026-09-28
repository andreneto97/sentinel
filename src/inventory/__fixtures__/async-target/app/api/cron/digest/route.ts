/** Sends the digest. Called by the Vercel cron, and anybody else who asks. */
export async function GET(): Promise<Response> {
  await sendDigest();
  return new Response("sent");
}

async function sendDigest(): Promise<void> {
  await fetch("https://api.example.test/internal/digest", { method: "POST" });
}
