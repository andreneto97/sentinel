/** One endpoint a failed delivery is replayed against. */
export interface RetryTarget {
  readonly endpoint: string;
  readonly body: string;
}

/** Replays a failed delivery: a stored URL and a timeout, with nothing to verify. */
export async function replay(target: RetryTarget): Promise<number> {
  const sent = await fetch(target.endpoint, {
    method: "POST",
    body: target.body,
    signal: AbortSignal.timeout(5_000),
  });
  return sent.status;
}
