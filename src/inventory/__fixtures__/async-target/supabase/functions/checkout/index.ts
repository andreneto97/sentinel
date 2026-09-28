declare const Deno: { serve(handler: (request: Request) => Promise<Response>): void };

// Supabase edge function: HTTP-invoked, and `config.toml` turns JWT verification off.
Deno.serve(async (request: Request): Promise<Response> => {
  const body = await request.json();
  return new Response(JSON.stringify({ ok: true, body }), {
    headers: { "content-type": "application/json" },
  });
});
