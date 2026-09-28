import { NextResponse } from "next/server";

/** Edge runtime, so the serverless enumerator has something to disagree with. */
export const runtime = "edge";

/** Liveness probe. */
export const GET = async (): Promise<Response> => {
  return NextResponse.json({ ok: true });
};

/** Re-exported handler: the unit is the export, the code is elsewhere. */
async function optionsHandler(): Promise<Response> {
  return NextResponse.json({ allow: "GET" });
}

export { optionsHandler as OPTIONS };
