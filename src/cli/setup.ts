import type { ToolsLock } from "../contracts/tools.ts";
import {
  type FetchLike,
  type InstallResult,
  type ToolFileSystem,
  ToolInstallError,
  type ToolProcessExecutor,
  createToolInstaller,
  defaultCacheRoot,
  detectPlatform,
} from "../tools/installer.ts";
import type { CliContext, SetupInvocation } from "./index.ts";
import { EXIT } from "./index.ts";

/** Ports the command needs; nothing is reached for inside it. */
export interface SetupCliDeps {
  readonly fs: ToolFileSystem;
  readonly exec: ToolProcessExecutor;
  readonly fetch: FetchLike;
  readonly lock: ToolsLock;
  readonly cacheRoot?: string | undefined;
}

/** One line per tool, so a slow download does not look like a hang. */
function describeResult(result: InstallResult): string {
  const verb = result.status === "installed" ? "installed" : "already present";
  return `  [ok] ${result.name.padEnd(20)} ${result.version.padEnd(10)} ${verb}`;
}

/**
 * Remediation text per failure cause. A digest mismatch is deliberately blunt:
 * it is either a re-tagged release or a tampered artifact, and neither should
 * be worked around by installing anyway.
 */
function hintFor(error: ToolInstallError): string {
  switch (error.code) {
    case "digest-mismatch":
      return "The download did not match the pinned SHA-256. Nothing was installed. Do not retry blindly — verify the release, then refresh the pin with `bun run scripts/update-tools-lock.ts`.";
    case "unpinned":
      return "That tool has no pinned digest in tools.lock.json. Fill it in with `bun run scripts/update-tools-lock.ts` rather than installing an unverified binary.";
    case "download-failed":
      return "The release artifact could not be fetched. Check connectivity, then re-run `sentinel setup`.";
    case "no-space":
      return "Free space in the tool cache filesystem and re-run `sentinel setup`.";
    case "unsupported-platform":
      return "This platform is not in tools.lock.json. Sentinel runs its analyzers from pinned binaries, so there is no PATH fallback.";
    default:
      return "Re-run `sentinel setup`; if it persists, run with --verbose and report the tool name.";
  }
}

/** Install the pinned analysis tools into the Sentinel cache. */
export async function setupCommand(
  context: CliContext,
  invocation: SetupInvocation,
  deps: SetupCliDeps,
): Promise<number> {
  const platform = detectPlatform();
  if (platform === null) {
    context.writeError(
      `sentinel setup: unsupported platform ${process.platform}/${process.arch}.\n`,
    );
    return EXIT.preflight;
  }

  const cacheRoot = deps.cacheRoot ?? defaultCacheRoot(context.env);
  const installer = createToolInstaller({
    lock: deps.lock,
    fs: deps.fs,
    exec: deps.exec,
    fetch: deps.fetch,
    cacheRoot,
    platform,
  });

  const only = invocation.only;
  const quiet = invocation.output.quiet;
  if (!quiet && !invocation.output.json) {
    context.write(`Installing pinned tools into ${cacheRoot}\n`);
    context.write(`  platform ${platform}\n\n`);
  }

  const options = { force: invocation.force };
  const results: InstallResult[] = [];
  try {
    if (only === undefined) {
      results.push(...(await installer.installAll(options)));
    } else if (only in deps.lock.binaries) {
      results.push(await installer.installBinaryTool(only, options));
    } else if (only in deps.lock.node) {
      results.push(await installer.installNodeTool(only, options));
    } else {
      const known = [...Object.keys(deps.lock.binaries), ...Object.keys(deps.lock.node)].sort();
      context.writeError(
        `sentinel setup: unknown tool "${only}". Pinned tools: ${known.join(", ")}.\n`,
      );
      return EXIT.usage;
    }
  } catch (error) {
    if (invocation.output.json) {
      context.write(`${JSON.stringify({ ok: false, installed: results, error: String(error) })}\n`);
    } else {
      for (const result of results) context.write(`${describeResult(result)}\n`);
      const message = error instanceof Error ? error.message : String(error);
      context.writeError(`\nsentinel setup: ${message}\n`);
      if (error instanceof ToolInstallError) context.writeError(`  ${hintFor(error)}\n`);
    }
    return EXIT.failure;
  }

  if (invocation.output.json) {
    context.write(`${JSON.stringify({ ok: true, cacheRoot, platform, installed: results })}\n`);
    return EXIT.ok;
  }
  if (!quiet) {
    for (const result of results) context.write(`${describeResult(result)}\n`);
    const fresh = results.filter((result) => result.status === "installed").length;
    context.write(
      `\n${results.length} tool(s) ready, ${fresh} newly installed, every download SHA-256 verified.\n`,
    );
    context.write("Run `sentinel doctor` to confirm what the analysis can now cover.\n");
  }
  return EXIT.ok;
}
