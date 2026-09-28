import type {
  AnswerSource,
  DecidedProposal,
  NotApplicable,
  Proposal,
  ProposalCost,
  ScopeDecision,
  ScopeProposalDocument,
} from "../contracts/proposal.ts";
import { ScopeProposalDocumentSchema } from "../contracts/proposal.ts";

const WRAP_WIDTH = 92;

/** "+40s", "+2m", "+2m 30s" — how much longer the run gets. */
export function formatDuration(seconds: number): string {
  if (seconds < 60) return `+${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  return rest === 0 ? `+${minutes}m` : `+${minutes}m ${rest}s`;
}

/** One-line price tag: time, whether it spends AI, and any tool it needs. */
export function formatCost(cost: ProposalCost): string {
  const parts = [formatDuration(cost.estimatedSeconds), cost.usesAi ? "AI" : "no AI"];
  if (cost.requiresTool !== undefined) parts.push(`needs ${cost.requiresTool}`);
  return parts.join(" · ");
}

/** Greedy word wrap; keeps long `wouldCheck` prose readable in a terminal. */
function wrapText(text: string, width: number): string[] {
  const lines: string[] = [];
  let current = "";
  for (const word of text.split(/\s+/).filter((part) => part !== "")) {
    if (current === "") {
      current = word;
    } else if (current.length + 1 + word.length <= width) {
      current = `${current} ${word}`;
    } else {
      lines.push(current);
      current = word;
    }
  }
  if (current !== "") lines.push(current);
  return lines.length > 0 ? lines : [""];
}

function block(label: string, text: string, indent: string): string[] {
  const gutter = " ".repeat(label.length + 1);
  const lines = wrapText(text, WRAP_WIDTH - indent.length - label.length - 1);
  return lines.map((line, index) =>
    index === 0 ? `${indent}${label} ${line}` : `${indent}${gutter}${line}`,
  );
}

/**
 * The numbered list the operator answers. Every entry shows what was found,
 * what would run, what it costs, and the exact selector to answer with.
 */
export function renderProposalList(proposals: readonly Proposal[]): string {
  if (proposals.length === 0) {
    return "Sentinel found nothing outside the current scope. Everything it detected is checked.";
  }
  const lines: string[] = [
    `Sentinel found ${proposals.length} thing(s) it will not check under the current scope.`,
    "",
  ];
  proposals.forEach((proposal, index) => {
    const number = `${index + 1}`.padStart(2, " ");
    lines.push(`${number}. ${proposal.title}  [${proposal.domain} · ${formatCost(proposal.cost)}]`);
    lines.push(...block("Found    ", proposal.detected.summary, "    "));
    if (proposal.detected.evidence.length > 0) {
      lines.push(...block("Evidence ", proposal.detected.evidence.join(", "), "    "));
    }
    lines.push(...block("Would do ", proposal.wouldCheck, "    "));
    lines.push(`    Default   ${proposal.defaultAnswer}   (--include ${proposal.id})`);
    lines.push("");
  });
  lines.push("Nothing here runs unless you say so: an unanswered proposal stays off.");
  return lines.join("\n");
}

function sourcePhrase(source: AnswerSource): string {
  switch (source) {
    case "flag":
      return "on the command line";
    case "config":
      return "remembered in sentinel.config.json";
    case "defaults":
      return "by --yes, taking the default";
    case "unanswered":
      return "never answered";
  }
}

function outcomePhrase(entry: DecidedProposal): string {
  switch (entry.outcome) {
    case "accepted":
      return `offered, accepted (${sourcePhrase(entry.source)})`;
    case "declined":
      return `offered, declined (${sourcePhrase(entry.source)})`;
    case "untouched":
      return "offered, not answered (stayed off)";
  }
}

function decidedLine(entry: DecidedProposal): string {
  const { proposal } = entry;
  return (
    `- **${proposal.title}** (\`${proposal.id}\`) — ${outcomePhrase(entry)}. ` +
    `${proposal.detected.summary}. Cost if run: ${formatCost(proposal.cost)}.`
  );
}

function notApplicableLine(entry: NotApplicable): string {
  return `- **${entry.category}** (\`${entry.id}\`) — not applicable. ${entry.reason}`;
}

function section(title: string, lines: readonly string[]): string[] {
  if (lines.length === 0) return [];
  return [`### ${title}`, "", ...lines, ""];
}

/**
 * The report's scope section. Declined and unanswered proposals are printed
 * with the same weight as accepted ones — that is the whole point of phase 0.5.
 */
export function renderScopeSection(decision: ScopeDecision): string {
  const offered = decision.accepted.length + decision.declined.length + decision.untouched.length;
  const lines: string[] = [
    "## Scope negotiation",
    "",
    `Sentinel offered ${offered} extra check(s): ${decision.accepted.length} accepted, ${decision.declined.length} declined, ${decision.untouched.length} never answered. Anything not accepted was **not** checked.`,
    "",
    `Domains enabled: ${decision.enabledDomains.join(", ") || "none"}.`,
    "",
  ];
  lines.push(...section("Accepted", decision.accepted.map(decidedLine)));
  lines.push(...section("Declined", decision.declined.map(decidedLine)));
  lines.push(
    ...section("Offered, never answered (stayed off)", decision.untouched.map(decidedLine)),
  );
  lines.push(...section("Not applicable", decision.notApplicable.map(notApplicableLine)));
  if (decision.blockedOnMissingTool.length > 0) {
    lines.push(
      ...section(
        "Accepted but blocked",
        decision.blockedOnMissingTool.map(
          (entry) =>
            `- \`${entry.proposalId}\` was accepted, but \`${entry.tool}\` is not installed, so it did not run.`,
        ),
      ),
    );
  }
  if (decision.unknownSelectors.length > 0) {
    lines.push(
      ...section(
        "Unrecognised selectors",
        decision.unknownSelectors.map((selector) => `- \`${selector}\` matched nothing.`),
      ),
    );
  }
  return `${lines.join("\n").trimEnd()}\n`;
}

/** Short terminal confirmation of the resolved scope, printed before the run. */
export function renderScopeSummary(decision: ScopeDecision): string {
  const lines = [
    `Domains: ${decision.enabledDomains.join(", ") || "none"}`,
    `Accepted: ${decision.accepted.length} (${formatDuration(decision.estimatedExtraSeconds)}` +
      `, ${decision.usesAi ? "spends AI" : "no AI"})`,
    `Declined: ${decision.declined.length}`,
    `Never answered (off): ${decision.untouched.length}`,
    `Not applicable: ${decision.notApplicable.length}`,
  ];
  for (const entry of decision.untouched) {
    lines.push(`  - not answered, stayed off: ${entry.proposal.id}`);
  }
  return lines.join("\n");
}

/** The validated `scope-proposal.json` payload, ready for an atomic write. */
export function renderScopeProposalJson(document: ScopeProposalDocument): string {
  return `${JSON.stringify(ScopeProposalDocumentSchema.parse(document), null, 2)}\n`;
}
