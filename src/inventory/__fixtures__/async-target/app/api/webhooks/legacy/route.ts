/** Legacy receiver: parses JSON and trusts whatever arrives. */
export async function POST(request: Request): Promise<Response> {
  const body = await request.json();
  await apply(body);
  return new Response("ok");
}

async function apply(body: unknown): Promise<void> {
  await fetch("https://api.example.test/internal/legacy", {
    method: "POST",
    body: JSON.stringify(body),
  });
}
