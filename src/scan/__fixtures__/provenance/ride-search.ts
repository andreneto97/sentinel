// Pins the reachable shape and its closed sibling side by side: a default-exported
// express handler whose request field reaches a `DataSource.query` statement
// through the one call site in this file, and a second statement in the same file
// whose column is closed by an `as const` array. `Request`, `Response` and
// `NextFunction` are declared here so the fixture compiles with no dependency
// added -- the analyser reads the `req: Request` annotation, not the import.

import DataSource from "@fleet/db/client";

interface Request {
  auth: { operatorId: string };
  query: Record<string, unknown>;
}

interface Response {
  json(body: unknown): void;
}

type NextFunction = (error?: unknown) => void;

const ALLOWED_SORTS = ["started_at", "ended_at"] as const;

function searchRides(operatorId: string, sort: string) {
  return DataSource.query(`SELECT id FROM rides WHERE operator_id = $1 ORDER BY ${sort}`, [
    operatorId,
  ]);
}

function listRides(operatorId: string, column: (typeof ALLOWED_SORTS)[number]) {
  return DataSource.query(`SELECT id FROM rides WHERE operator_id = $1 ORDER BY ${column}`, [
    operatorId,
  ]);
}

export default async (req: Request, res: Response, next: NextFunction) => {
  try {
    const rows = await searchRides(req.auth.operatorId, req.query.sort as string);
    res.json(rows);
  } catch (error) {
    next(error);
  }
};

export const listHandler = async (req: Request, res: Response) => {
  res.json(await listRides(req.auth.operatorId, "started_at"));
};
