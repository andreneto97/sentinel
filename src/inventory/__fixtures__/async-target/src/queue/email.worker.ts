import { Worker } from "bullmq";

interface EmailJob {
  data: { to: string; body: string };
}

/** Sends one queued email. Nothing here deduplicates, and there is no DLQ. */
export const emailWorker = new Worker(
  "email",
  async (job: EmailJob): Promise<void> => {
    await deliver(job.data.to, job.data.body);
  },
  { concurrency: 25, lockDuration: 30000 },
);

async function deliver(to: string, body: string): Promise<void> {
  await fetch("https://mail.example.test/send", {
    method: "POST",
    body: JSON.stringify({ to, body }),
  });
}
