/** Dock telemetry receiver: parses JSON and trusts whatever arrives. */
export async function POST(request: Request): Promise<Response> {
  const body = await request.json();
  await record(body);
  return new Response("ok");
}

async function record(body: unknown): Promise<void> {
  await fetch("https://api.example.test/internal/dock-telemetry", {
    method: "POST",
    body: JSON.stringify(body),
  });
}
