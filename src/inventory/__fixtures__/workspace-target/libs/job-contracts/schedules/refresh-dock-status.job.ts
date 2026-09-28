import { Queue } from "bullmq";

const queue = new Queue("dock-status-refresh");

/**
 * A BullMQ repeatable job: scheduled work that no cron rule finds.
 *
 * A `repeat` option on a queue job, started on boot, is invisible to every cron
 * source a scanner globs for, so a repository whose only schedule looks like
 * this reads as declaring no scheduled work at all.
 */
export async function scheduleDockStatusRefresh(): Promise<void> {
  await queue.add(
    "dock-status-refresh",
    {},
    {
      jobId: "dock-status-refresh",
      repeatJobKey: "dock-status-refresh",
      repeat: { every: 5000, key: "dock-status-refresh" },
    },
  );
}
