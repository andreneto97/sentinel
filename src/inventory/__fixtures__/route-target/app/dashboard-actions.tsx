import { db } from "../src/lib/db.ts";

/** A component-file action: the directive is inside the function, not the file. */
export function useDashboard(): { reload: (teamId: string) => Promise<unknown[]> } {
  async function reload(teamId: string): Promise<unknown[]> {
    "use server";
    return await db.post.findMany({ where: { teamId } });
  }
  return { reload };
}
