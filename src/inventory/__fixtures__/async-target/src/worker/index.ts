// Cloudflare Worker entry: an HTTP handler and a cron handler in one module.
export default {
  async fetch(request: Request): Promise<Response> {
    return new Response(`hello ${request.url}`);
  },
  async scheduled(event: { cron: string }): Promise<void> {
    await fetch(`https://example.test/refresh?cron=${event.cron}`);
  },
};
