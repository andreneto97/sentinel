// Pins two fields of an imported configuration module interpolated into one
// statement: neither is caller input, so the statement is `config` rather than
// closed, and the two parts stay distinct.

import config from "@fleet/config";
import DataSource from "@fleet/db/client";

export class RideSyncQueueWorker {
  public async resetStaleProcessingRows(): Promise<{ pending: number }> {
    const [rows]: [{ status: string }[]] = await DataSource.query(
      `WITH stale AS (
         SELECT id, ride_id, station_id, source_table
         FROM ride_sync_queue
         WHERE status = $1::ride_sync_queue_status_enum
           AND updated_at < NOW() - INTERVAL '${config.RIDE_SYNC_STALE_SECONDS} seconds'
           AND retired_at IS NULL
         ORDER BY updated_at
         FETCH FIRST ${config.RIDE_SYNC_STALE_LIMIT} ROWS ONLY
         FOR UPDATE SKIP LOCKED
       )
       UPDATE ride_sync_queue SET status = $2 WHERE id IN (SELECT id FROM stale) RETURNING status`,
      ["PROCESSING", "PENDING"],
    );
    return { pending: rows.length };
  }
}
