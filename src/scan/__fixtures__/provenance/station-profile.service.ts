// Pins `.map(...).join(...)` over an `as const` tuple, with a nested `.map`
// result read back by index: every fragment that reaches the statement belongs to
// a fixed compile-time set, even though the caller chooses which of them apply.

import DataSource from "@fleet/db/client";

interface StationProfileUpsertParams {
  stationId: string;
  fields: Record<string, string>;
  profileUpdatedAt?: Date;
}

const PROFILE_COLUMNS = [
  ["displayName", "display_name"],
  ["neighbourhood", "neighbourhood"],
  ["capacity", "capacity"],
  ["kioskLabel", "kiosk_label"],
] as const;

export class StationProfileService {
  async upsert(params: StationProfileUpsertParams): Promise<boolean> {
    const profileUpdatedAt = params.profileUpdatedAt ?? new Date();

    const insertValues = PROFILE_COLUMNS.map(([field]) => params.fields[field] ?? null);
    const setExpressions = PROFILE_COLUMNS.map(([field, column]) =>
      field in params.fields ? `EXCLUDED.${column}` : `station_profiles.${column}`,
    );
    const setClause = PROFILE_COLUMNS.map(
      ([, column], i) => `${column} = ${setExpressions[i]}`,
    ).join(", ");
    const changedClause = PROFILE_COLUMNS.map(
      ([, column], i) => `(${setExpressions[i]}) IS DISTINCT FROM station_profiles.${column}`,
    ).join(" OR ");

    const written = await DataSource.query(
      `INSERT INTO station_profiles (station_id, display_name, neighbourhood, capacity, kiosk_label, profile_updated_at, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, now(), now())
       ON CONFLICT (station_id) DO UPDATE SET
         ${setClause},
         profile_updated_at = $6,
         updated_at = now()
       WHERE station_profiles.retired_at IS NULL
         AND (${changedClause})
       RETURNING station_id`,
      [params.stationId, ...insertValues, profileUpdatedAt],
    );

    return written.length > 0;
  }
}
