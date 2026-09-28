import cron from "node-cron";

/** Deletes expired sessions every night; no lock, so two instances overlap. */
export function scheduleCleanup(): void {
  cron.schedule("0 4 * * *", async () => {
    await purgeSessions();
  });
}

async function purgeSessions(): Promise<void> {
  await fetch("https://api.example.test/internal/purge", { method: "POST" });
}
