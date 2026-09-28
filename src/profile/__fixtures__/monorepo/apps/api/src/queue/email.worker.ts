import { Worker } from "bullmq";

/** Consumes the transactional email queue. */
export const emailWorker = new Worker("email", async (job: { data: unknown }) => {
  await Promise.resolve(job.data);
});
