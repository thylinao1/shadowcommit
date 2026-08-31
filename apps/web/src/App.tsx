import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError, setAuthToken, type CapabilityGrant } from "./api";
import { ReviewsPanel } from "./components/reviews/ReviewsPanel";
import { RunTimeline } from "./components/timeline/RunTimeline";
import { Spinner } from "./components/ui/Spinner";
import { TransactionsBadge } from "./components/ui/TransactionsBadge";
import { usePolling } from "./hooks/usePolling";
import { formatTime } from "./lib/format";
import {
  readMessage,
  verdictOfContainment,
  verdictOfTurn,
  verdictSentence,
  verdictTone,
} from "./lib/verdict";
import type {
  Agent,
  AgentRun,
  JournalResponse,
  Message,
  Review,
  SystemInfo,
} from "./types";

/** Which of the three screens the main column is showing. */
type View = "playground" | "timeline" | "reviews";

/** How often the panel asks the server what is true. A live stream is a later lane. */
const POLL_MS = 2_000;

const starterPrompts = [
  "Create a small TypeScript CLI that prints a weather summary from sample JSON.",
  "Inspect this workspace and explain what you would improve first.",
  "Build a responsive single-page todo app with tests.",
];

const emptyForm = {
  name: "",
  description: "",
  instructions:
    "Help me build and test software in this workspace. Keep changes small and explain the result.",
};

/**
 * What the panel knows about one Agent's capability grant. A grant it could not read is its own
 * state: showing the open default instead would tell an operator their Agent is unrestricted when
 * the truth is that this panel does not know.
 */
type GrantState =
  | { status: "loading" }
  | { status: "ready"; grant: CapabilityGrant }
  | { status: "error"; message: string };

/**
 * What the grant says right now, in a sentence a person can act on.
 *
 * Three states and each one is different on purpose. A grant that could not be read says so rather
 * than falling back to the default, because a control that looks like it is protecting you when it
 * is not is worse than no control. The synthesised default says it is a default and says what it
 * allows, so nobody reads `**` in a form and thinks somebody chose it. It also says what the check
 * still does with no grant configured, because "inert until configured" is not true: it holds a
 * turn whose path leaves the workspace or whose destination will not parse, whatever the grant.
 */
export function CapabilityGrantStatus({
  state,
  onRetry,
}: {
  state: GrantState;
  onRetry: () => void;
}) {
  if (state.status === "loading") {
    return <p>Reading the grant in force for this Agent.</p>;
  }

  if (state.status === "error") {
    return (
      <div>
        <div className="error-banner" role="alert">
          The capability grant could not be read: {state.message}. That is this panel failing to ask,
          not a report that this Agent has no grant.
        </div>
        <button type="button" className="button button-ghost" onClick={onRetry}>
          Try reading the grant again
        </button>
      </div>
    );
  }

  const { grant } = state;
  if (grant.source === "default") {
    return (
      <p>
        No grant has been issued for this Agent, so the server is using the open default: every path
        in the workspace, every destination, and no practical ceiling on effects in a turn. The
        fields below show that default, not a decision anybody made, and saving them unchanged
        records that open grant as revision 1 under your name. The check does still run and still
        holds a turn whose path leaves the workspace or whose destination cannot be parsed, but it
        authorizes everything well formed until you narrow it here.
      </p>
    );
  }

  /**
   * Two sentences that used to be one. `revoke` on an Agent nobody ever issued a grant to
   * synthesises a default grant, stamps `issuedBy: "default"` and a fresh timestamp on it, and
   * bumps past revision 1, so the panel read "Revision 2, issued by default at 10:04" for a grant
   * no operator ever created. That is a made-up attribution, and there is no way to make it true,
   * so the attribution is dropped for that case rather than reworded.
   */
  const attribution =
    grant.issuedBy === "default"
      ? "Revision " + grant.revision + ", carried forward from the server's open default rather than from a grant anybody issued."
      : "Revision " + grant.revision + ", issued by " + grant.issuedBy + " at " + formatTime(grant.issuedAt) + ".";

  return (
    <p>
      {attribution}{" "}
      {grant.status === "revoked"
        ? "Revoked" +
          (grant.revokedBy ? " by " + grant.revokedBy : "") +
          ". Every turn this Agent proposes that carries an effect at all is held for a person from the next judgement on, including one running right now. A turn that proposes nothing is not authorized and not held. A turn already waiting in the review queue is still yours to approve or reject."
        : "In force. The policy reads it when a turn is judged, so a change here reaches the turn that is running now."}
    </p>
  );
}

/**
 * One entry per line, and one per comma inside a line, blanks dropped. What an operator types,
 * not a JSON array.
 *
 * The comma split skips a line that contains a brace, because a brace glob has commas INSIDE it.
 * Splitting `src/{a,b}/**` on every comma produced `src/{a` and `b}/**`, and both halves passed
 * validation, were stored as the operator's authorization scope, and matched nothing at all:
 * `globExpression` escapes braces, so neither half can ever match a path. The operator narrowed
 * the grant, saw a saved revision, and every later turn was held under
 * `capability-path-out-of-scope` with nothing on the screen saying their input had been cut in
 * half. A line with a brace is taken whole and left for the server to accept or refuse.
 */
export function parseScopeList(text: string): string[] {
  const entries: string[] = [];
  for (const line of text.split("\n")) {
    const pieces = line.includes("{") || line.includes("}") ? [line] : line.split(",");
    for (const piece of pieces) {
      const entry = piece.trim();
      if (entry.length > 0) entries.push(entry);
    }
  }
  return entries;
}

export const scopeText = (entries: readonly string[]): string => entries.join("\n");

export interface GrantFormValues {
  pathGlobs: string;
  destinations: string;
  budget: string;
}

/**
 * What the three fields mean, decided here rather than in the submit handler so it can be tested
 * and so a refusal names the field it is about. An empty list is refused rather than sent: the
 * server would reject it too, but "give at least one path glob" is a better sentence than a 400,
 * and a grant that allows nothing is never what an operator meant to type.
 *
 * The shape checks below are the server's own, applied here so the operator gets a sentence about
 * the field instead of a 500. `normalizeCapabilityGrantInput` throws a plain `TypeError` for a
 * glob that is absolute or has a `.`/`..` segment and for a destination carrying `://`, `@`, `?`,
 * `#` or whitespace, and `app.ts` maps only `ZodError` and `HttpError` to a 4xx, so every one of
 * those reached the browser as HTTP 500 with the TypeError text as the body. Measured: `/etc/**`,
 * `../**`, `./src/**`, `https://api.example.com`, `https://api.example.com/v1`,
 * `user@example.com`, `a b.com` and `example.com/?x=1` were all accepted by this form and answered
 * with a 500. Typing a URL into a box labelled destinations is the likeliest thing an operator
 * does with it.
 *
 * Budget is read as digits rather than through `Number`, because `Number` accepted `0x10` as 16,
 * `1e3` as 1000, `+3` as 3 and `5.0` as 5 under a refusal message promising "a whole number".
 */
const PATH_GLOB_RULE =
  "Path globs are workspace-relative: no leading slash, no drive letter, and no . or .. segment.";
const DESTINATION_RULE =
  "Destinations are host[:port][/path-glob], or a single * for every destination. No scheme, no @, no ?, no #, no spaces.";

function badPathGlob(glob: string): boolean {
  const candidate = glob.replaceAll("\\", "/");
  return (
    candidate.startsWith("/") ||
    /^[A-Za-z]:/.test(candidate) ||
    candidate.split("/").some((part) => part === "." || part === "..")
  );
}

function badDestination(destination: string): boolean {
  if (destination === "*") return false;
  if (/:\/\/|[@?#]|\s/.test(destination)) return true;
  return (destination.split("/", 1)[0] ?? "").length === 0;
}

export function validateGrantForm(
  values: GrantFormValues,
): { ok: true; body: { allowedPathGlobs: string[]; allowedDestinations: string[]; budget: number } } | { ok: false; message: string } {
  const allowedPathGlobs = parseScopeList(values.pathGlobs);
  const allowedDestinations = parseScopeList(values.destinations);
  const trimmed = values.budget.trim();
  if (allowedPathGlobs.length === 0) {
    return { ok: false, message: "Give at least one path glob. An empty list would be a grant that allows nothing." };
  }
  const rejectedGlob = allowedPathGlobs.find(badPathGlob);
  if (rejectedGlob !== undefined) {
    return { ok: false, message: "The path glob " + rejectedGlob + " cannot be used. " + PATH_GLOB_RULE };
  }
  if (allowedDestinations.length === 0) {
    return { ok: false, message: "Give at least one destination, or a single * to allow every destination." };
  }
  const rejectedDestination = allowedDestinations.find(badDestination);
  if (rejectedDestination !== undefined) {
    return { ok: false, message: "The destination " + rejectedDestination + " cannot be used. " + DESTINATION_RULE };
  }
  const budget = Number(trimmed);
  if (!/^[0-9]+$/.test(trimmed) || !Number.isSafeInteger(budget)) {
    return { ok: false, message: "Budget is the maximum number of effects in one turn: a whole number in digits, zero or more." };
  }
  return { ok: true, body: { allowedPathGlobs, allowedDestinations, budget } };
}

function StatusPill({ status }: { status: Agent["status"] }) {
  return (
    <span className={"status status-" + status}>
      <span className="status-dot" />
      {status}
    </span>
  );
}

export default function App() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [system, setSystem] = useState<SystemInfo | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [form, setForm] = useState(emptyForm);
  const [prompt, setPrompt] = useState("");
  const [activeRun, setActiveRun] = useState<AgentRun | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [authRequired, setAuthRequired] = useState<boolean | null>(null);
  const [authInput, setAuthInput] = useState("");
  const [view, setView] = useState<View>("playground");
  const [reviews, setReviews] = useState<Review[]>([]);
  const [journal, setJournal] = useState<JournalResponse | null>(null);
  const [settling, setSettling] = useState<string | null>(null);
  const [runs, setRuns] = useState<AgentRun[]>([]);
  const [grant, setGrant] = useState<GrantState>({ status: "loading" });
  const [grantForm, setGrantForm] = useState({ pathGlobs: "", destinations: "", budget: "" });
  const [grantBusy, setGrantBusy] = useState(false);
  const [grantError, setGrantError] = useState<string | null>(null);
  const [grantSaved, setGrantSaved] = useState<string | null>(null);
  const messageEnd = useRef<HTMLDivElement>(null);
  const selectedIdRef = useRef<string | null>(null);
  const mountedRef = useRef(true);
  const pollingRunIds = useRef(new Set<string>());
  selectedIdRef.current = selectedId;

  const selected = useMemo(
    () => agents.find((agent) => agent.id === selectedId) ?? null,
    [agents, selectedId],
  );

  const refreshAgents = useCallback(async () => {
    const { agents: next } = await api.listAgents();
    setAgents(next);
    setSelectedId((current) =>
      current && next.some((agent) => agent.id === current)
        ? current
        : (next[0]?.id ?? null),
    );
  }, []);

  const refreshMessages = useCallback(async (agentId: string) => {
    const result = await api.messages(agentId);
    if (mountedRef.current && selectedIdRef.current === agentId) {
      setMessages(result.messages);
    }
  }, []);

  const bootstrap = useCallback(async () => {
    await Promise.all([refreshAgents(), api.system().then(setSystem)]);
  }, [refreshAgents]);

  useEffect(() => {
    mountedRef.current = true;
    void api
      .auth()
      .then(async ({ required }) => {
        if (!mountedRef.current) return;
        setAuthRequired(required);
        if (!required) await bootstrap();
      })
      .catch((reason) => setError(reason instanceof Error ? reason.message : String(reason)));
    return () => {
      mountedRef.current = false;
    };
  }, [bootstrap]);

  useEffect(() => {
    setActiveRun(null);
    setShowSettings(false);
    if (!selectedId) {
      setMessages([]);
      return;
    }
    void Promise.all([refreshMessages(selectedId), api.runs(selectedId)])
      .then(([, result]) => {
        if (selectedIdRef.current !== selectedId) return;
        const latest = result.runs[0] ?? null;
        setActiveRun(latest);
        if (latest && ["queued", "running"].includes(latest.status)) {
          void pollRun(latest.id, selectedId).catch((reason) =>
            setError(reason instanceof Error ? reason.message : String(reason)),
          );
        }
      })
      .catch((reason) =>
        setError(reason instanceof Error ? reason.message : String(reason)),
      );
  }, [refreshMessages, selectedId]);

  useEffect(() => {
    if (selected) {
      setForm({
        name: selected.name,
        description: selected.description,
        instructions: selected.instructions,
      });
    }
  }, [selected]);

  useEffect(() => {
    messageEnd.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, activeRun]);

  const refreshReviews = useCallback(async () => {
    const { reviews: next } = await api.reviews();
    if (mountedRef.current) setReviews(next);
  }, []);

  const refreshJournal = useCallback(async (agentId: string) => {
    const [next, runList] = await Promise.all([api.journal(agentId), api.runs(agentId)]);
    if (mountedRef.current && selectedIdRef.current === agentId) {
      setJournal(next);
      setRuns(runList.runs);
    }
  }, []);

  // Two seconds is fast enough that a held turn appears while a viewer is still reading the reply
  // that produced it, and slow enough to stay honest about being a poll rather than a stream.
  usePolling(
    () => refreshReviews().catch(() => undefined),
    POLL_MS,
    authRequired === false,
  );

  usePolling(
    () => (selectedId ? refreshJournal(selectedId).catch(() => undefined) : undefined),
    POLL_MS,
    authRequired === false && selectedId != null,
  );

  useEffect(() => {
    setJournal(null);
    setRuns([]);
  }, [selectedId]);

  /**
   * What the boundary did with a turn, by the id of the run that produced it, in order of
   * authority. The journal is the record and wins. A containment field on the run is next, and it
   * is what makes a committed turn readable here: the runner deliberately appends nothing to the
   * reply on a commit, so the reply alone cannot say how many changes landed.
   *
   * The journal keys turns by the transaction id, which today is not the same identifier as the run
   * id, so the first source only fires once the two are linked. See LANE-REPORT.md.
   */
  const verdictByRun = useMemo(() => {
    const map = new Map<string, ReturnType<typeof verdictOfTurn>>();
    for (const run of runs) {
      if (run.containment) map.set(run.id, verdictOfContainment(run.containment));
    }
    for (const turn of journal?.turns ?? []) map.set(turn.runId, verdictOfTurn(turn));
    return map;
  }, [journal, runs]);

  const settleReview = async (review: Review, decision: "approve" | "reject") => {
    setSettling(review.runId);
    setError(null);
    try {
      if (decision === "approve") {
        await api.approveReview(review.runId, review.effectSetHash);
      } else {
        await api.rejectReview(review.runId);
      }
      await refreshReviews();
      if (selectedIdRef.current) await refreshJournal(selectedIdRef.current);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
      await refreshReviews().catch(() => undefined);
    } finally {
      setSettling(null);
    }
  };

  const openAgent = (agentId: string) => {
    setSelectedId(agentId);
    setView("timeline");
  };

  const createAgent = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { agent } = await api.createAgent(form);
      await refreshAgents();
      setSelectedId(agent.id);
      setShowCreate(false);
      setForm(emptyForm);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  /**
   * Reads the grant in force for this Agent and fills the form with it.
   *
   * The response says `source: "stored"` when an operator issued it and `"default"` when nobody has
   * and the server synthesised the open one. The panel keeps that distinction all the way to the
   * screen, because a form pre-filled with `**` and `*` looks exactly like a grant somebody chose.
   */
  const refreshGrant = useCallback(async (agentId: string) => {
    setGrant({ status: "loading" });
    setGrantError(null);
    setGrantSaved(null);
    try {
      const { grant: current } = await api.capabilityGrant(agentId);
      if (selectedIdRef.current !== agentId) return;
      setGrant({ status: "ready", grant: current });
      setGrantForm({
        pathGlobs: scopeText(current.allowedPathGlobs),
        destinations: scopeText(current.allowedDestinations),
        budget: String(current.budget),
      });
    } catch (reason) {
      if (selectedIdRef.current !== agentId) return;
      setGrant({
        status: "error",
        message: reason instanceof Error ? reason.message : String(reason),
      });
    }
  }, []);

  useEffect(() => {
    if (!showSettings || !selectedId) return;
    void refreshGrant(selectedId);
  }, [refreshGrant, selectedId, showSettings]);

  const saveGrant = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!selected) return;
    const checked = validateGrantForm(grantForm);
    if (!checked.ok) {
      setGrantError(checked.message);
      return;
    }
    setGrantBusy(true);
    setGrantError(null);
    setGrantSaved(null);
    try {
      const { grant: issued } = await api.issueCapabilityGrant(selected.id, checked.body);
      // The PUT response has no `source`: only the GET path adds one. It is stored by definition,
      // because a store.issue that just returned is what the next GET will read back.
      setGrant({ status: "ready", grant: { ...issued, source: "stored" } });
      setGrantForm({
        pathGlobs: scopeText(issued.allowedPathGlobs),
        destinations: scopeText(issued.allowedDestinations),
        budget: String(issued.budget),
      });
      // the same mechanism the status paragraph above describes, said the same way. "From the next
      // turn this Agent is judged" read as excluding the turn that is running, and the grant is
      // read AT judgement, so it does not exclude it.
      setGrantSaved(
        "Revision " +
          issued.revision +
          " is in force. The policy reads the grant when a turn is judged, so this reaches the turn that is running now.",
      );
    } catch (reason) {
      setGrantError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setGrantBusy(false);
    }
  };

  const revokeGrant = async () => {
    if (!selected) return;
    if (
      !window.confirm(
        "Revoke the capability grant for " +
          selected.name +
          "? Every turn it proposes from the next judgement on is held for a person.",
      )
    ) {
      return;
    }
    setGrantBusy(true);
    setGrantError(null);
    setGrantSaved(null);
    try {
      const { grant: revoked } = await api.revokeCapabilityGrant(selected.id);
      setGrant({ status: "ready", grant: { ...revoked, source: "stored" } });
      setGrantSaved(
        "Revoked at revision " +
          revoked.revision +
          ". Every turn that carries an effect is held from the next judgement on, including one running now.",
      );
    } catch (reason) {
      setGrantError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setGrantBusy(false);
    }
  };

  const saveAgent = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      await api.updateAgent(selected.id, form);
      await refreshAgents();
      setShowSettings(false);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const toggleAgent = async () => {
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      if (selected.status === "stopped") {
        await api.startAgent(selected.id);
      } else {
        await api.stopAgent(selected.id);
      }
      await refreshAgents();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const deleteAgent = async () => {
    if (!selected) return;
    if (!window.confirm("Delete " + selected.name + "? Its workspace will be archived.")) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.deleteAgent(selected.id);
      await refreshAgents();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const pollRun = async (runId: string, agentId: string) => {
    if (pollingRunIds.current.has(runId)) return;
    pollingRunIds.current.add(runId);
    try {
      while (mountedRef.current) {
        await new Promise((resolve) => window.setTimeout(resolve, 900));
        if (!mountedRef.current) return;
        const result = await api.run(runId);
        if (selectedIdRef.current === agentId) setActiveRun(result.run);
        if (!["queued", "running"].includes(result.run.status)) {
          await Promise.all([refreshMessages(agentId), refreshAgents()]);
          return;
        }
      }
    } finally {
      pollingRunIds.current.delete(runId);
    }
  };

  const sendMessage = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!selected || !prompt.trim()) return;
    const content = prompt.trim();
    setPrompt("");
    setError(null);
    try {
      const result = await api.sendMessage(selected.id, content);
      if (selectedIdRef.current === selected.id) {
        setMessages((current) => [...current, result.message]);
        setActiveRun(result.run);
      }
      setAgents((current) =>
        current.map((agent) =>
          agent.id === selected.id ? { ...agent, status: "busy" } : agent,
        ),
      );
      await pollRun(result.run.id, selected.id);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
      setActiveRun(null);
      await refreshAgents();
    }
  };

  const unlock = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setAuthToken(authInput);
    try {
      await bootstrap();
      setAuthRequired(false);
      setAuthInput("");
    } catch (reason) {
      if (reason instanceof ApiError && reason.status === 401) {
        setError("The access token is not valid.");
      } else {
        setError(reason instanceof Error ? reason.message : String(reason));
      }
    } finally {
      setBusy(false);
    }
  };

  if (authRequired === null) {
    return (
      <main className="auth-screen">
        <section className="auth-card" aria-live="polite">
          <div className="brand-mark">A</div>
          <span className="eyebrow">Agent Launchpad</span>
          <h1>Connecting to the control plane</h1>
          {error ? <div className="error-banner" role="alert">{error}</div> : <Spinner />}
        </section>
      </main>
    );
  }

  if (authRequired) {
    return (
      <main className="auth-screen">
        <form className="auth-card" onSubmit={unlock}>
          <div className="brand-mark">A</div>
          <span className="eyebrow">Agent Launchpad</span>
          <h1>Enter the access token</h1>
          <p>This shared demo token is configured by the platform operator.</p>
          {error && <div className="error-banner" role="alert">{error}</div>}
          <label>
            Access token
            <input
              autoFocus
              type="password"
              value={authInput}
              onChange={(event) => setAuthInput(event.target.value)}
              autoComplete="current-password"
              required
            />
          </label>
          <button className="button button-primary" disabled={busy || !authInput.trim()}>
            {busy ? <Spinner /> : "Open Launchpad"}
          </button>
        </form>
      </main>
    );
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">A</div>
          <div>
            <strong>Agent Launchpad</strong>
            <span>Shadow Commit: preview and undo on every turn</span>
          </div>
        </div>

        <button
          className="button button-primary create-button"
          onClick={() => {
            setForm(emptyForm);
            setShowCreate(true);
          }}
        >
          <span>＋</span> Create Agent
        </button>

        <button
          className={"queue-button " + (view === "reviews" ? "selected" : "")}
          onClick={() => setView("reviews")}
          aria-current={view === "reviews"}
        >
          <span className="queue-copy">
            <strong>Review queue</strong>
            <span>{reviews.length === 0 ? "Nothing waiting" : "Proposed changes waiting"}</span>
          </span>
          <span className={"queue-count " + (reviews.length > 0 ? "queue-live" : "")}>{reviews.length}</span>
        </button>

        <div className="sidebar-label">
          <span>Your Agents</span>
          <span>{agents.length}</span>
        </div>
        <nav className="agent-list">
          {agents.map((agent) => (
            <button
              className={"agent-card " + (agent.id === selectedId && view !== "reviews" ? "selected" : "")}
              key={agent.id}
              onClick={() => {
                setSelectedId(agent.id);
                setView((current) => (current === "reviews" ? "playground" : current));
              }}
            >
              <div className="agent-avatar">{agent.name.slice(0, 1).toUpperCase()}</div>
              <div className="agent-card-copy">
                <strong>{agent.name}</strong>
                <span>{agent.description || "Coding Agent"}</span>
              </div>
              <TransactionsBadge compact />
              <span className={"mini-dot mini-" + agent.status} />
            </button>
          ))}
          {agents.length === 0 && (
            <div className="empty-sidebar">
              <span>◇</span>
              Create your first coding Agent.
            </div>
          )}
        </nav>

        <div className="runtime-card">
          <span className="eyebrow">Runtime</span>
          <strong>{system?.runtime ?? "Checking…"}</strong>
          <span>
            {system?.arkModel ?? "Ark model not configured"}
            {system?.containerEngine ? " · " + system.containerEngine : ""}
            {system?.runtimeProvider === "container" ? " · local container" : ""}
          </span>
        </div>
      </aside>

      <main className="main">
        {!system?.arkConfigured || !system?.codexAvailable ? (
          <div className="config-banner">
            <span>!</span>
            <div>
              <strong>Runtime configuration needed</strong>
              <p>
                {!system?.arkConfigured
                  ? "Set ARK_API_KEY and ARK_MODEL in .env before using the Playground."
                  : system.runtimeProvider === "container"
                    ? "The local container engine or Agent Runtime image is unavailable. Rerun npm run poc."
                    : "Codex CLI was not found. Use the Docker image or install @openai/codex."}
              </p>
            </div>
          </div>
        ) : null}

        {error && (
          <div className="error-banner" role="alert">
            <span>{error}</span>
            <button onClick={() => setError(null)}>×</button>
          </div>
        )}

        {view === "reviews" ? (
          <ReviewsPanel
            reviews={reviews}
            agents={agents}
            settling={settling}
            onApprove={(review) => void settleReview(review, "approve")}
            onReject={(review) => void settleReview(review, "reject")}
            onOpenAgent={openAgent}
          />
        ) : selected ? (
          <>
            <header className="agent-header">
              <div>
                <div className="header-title-row">
                  <h1>{selected.name}</h1>
                  <StatusPill status={selected.status} />
                  <TransactionsBadge />
                </div>
                <p>{selected.description || "A Codex coding Agent in an isolated workspace."}</p>
              </div>
              <div className="header-actions">
                <button
                  className="button button-ghost"
                  onClick={() => setShowSettings((value) => !value)}
                  disabled={busy || selected.status === "busy"}
                >
                  Settings
                </button>
                <button
                  className="button button-ghost"
                  onClick={toggleAgent}
                  disabled={busy}
                >
                  {selected.status === "stopped" ? "Start" : "Stop"}
                </button>
                <button
                  className="button button-danger"
                  onClick={deleteAgent}
                  disabled={busy || selected.status === "busy"}
                >
                  Delete
                </button>
              </div>
            </header>

            <nav className="view-tabs" aria-label="Agent views">
              <button
                className={"view-tab " + (view === "playground" ? "selected" : "")}
                aria-current={view === "playground"}
                onClick={() => setView("playground")}
              >
                Playground
              </button>
              <button
                className={"view-tab " + (view === "timeline" ? "selected" : "")}
                aria-current={view === "timeline"}
                onClick={() => setView("timeline")}
              >
                Run timeline
                {journal ? <span className="view-tab-count">{journal.turns.length}</span> : null}
              </button>
            </nav>

            {showSettings && (
              <form className="settings-panel" onSubmit={saveAgent}>
                <div className="settings-title">
                  <div>
                    <span className="eyebrow">Agent configuration</span>
                    <h2>Instructions and identity</h2>
                  </div>
                  <button type="button" onClick={() => setShowSettings(false)}>×</button>
                </div>
                <div className="form-grid">
                  <label>
                    Name
                    <input
                      value={form.name}
                      onChange={(event) => setForm({ ...form, name: event.target.value })}
                      required
                      maxLength={80}
                    />
                  </label>
                  <label>
                    Description
                    <input
                      value={form.description}
                      onChange={(event) =>
                        setForm({ ...form, description: event.target.value })
                      }
                      maxLength={500}
                    />
                  </label>
                </div>
                <label>
                  System instructions
                  <textarea
                    value={form.instructions}
                    onChange={(event) =>
                      setForm({ ...form, instructions: event.target.value })
                    }
                    rows={5}
                    maxLength={10_000}
                  />
                </label>
                <div className="panel-footer">
                  <code>{selected.workspacePath}</code>
                  <button className="button button-primary" disabled={busy}>
                    {busy ? <Spinner /> : "Save changes"}
                  </button>
                </div>
              </form>
            )}

            {showSettings && (
              <form className="settings-panel" onSubmit={saveGrant}>
                <div className="settings-title">
                  <div>
                    <span className="eyebrow">Capability grant</span>
                    <h2>What this Agent is allowed to touch</h2>
                  </div>
                </div>

                <p>
                  This is enforced in the policy, outside this panel and outside the Agent. Narrow it
                  and the next turn that steps past it is held for a person, whatever the Agent was
                  told to do.
                </p>

                <CapabilityGrantStatus state={grant} onRetry={() => void refreshGrant(selected.id)} />

                {grant.status === "ready" && (
                  <>
                    <label>
                      Allowed path globs, one per line
                      <textarea
                        value={grantForm.pathGlobs}
                        onChange={(event) =>
                          setGrantForm({ ...grantForm, pathGlobs: event.target.value })
                        }
                        rows={3}
                        spellCheck={false}
                      />
                    </label>

                    <label>
                      Allowed destinations, one per line, as host, host:port or host/path
                      <textarea
                        value={grantForm.destinations}
                        onChange={(event) =>
                          setGrantForm({ ...grantForm, destinations: event.target.value })
                        }
                        rows={3}
                        spellCheck={false}
                      />
                    </label>

                    <label>
                      Budget: the most effects one turn may propose
                      <input
                        value={grantForm.budget}
                        onChange={(event) =>
                          setGrantForm({ ...grantForm, budget: event.target.value })
                        }
                        inputMode="numeric"
                      />
                    </label>

                    {grantError && (
                      <div className="error-banner" role="alert">
                        {grantError}
                      </div>
                    )}
                    {grantSaved && <p>{grantSaved}</p>}

                    <div className="panel-footer">
                      <button
                        type="button"
                        className="button button-danger"
                        disabled={grantBusy}
                        onClick={() => void revokeGrant()}
                      >
                        Revoke
                      </button>
                      <button className="button button-primary" disabled={grantBusy}>
                        {grantBusy ? <Spinner /> : "Save grant"}
                      </button>
                    </div>
                  </>
                )}
              </form>
            )}

            {view === "timeline" ? (
              <RunTimeline journal={journal} agentName={selected.name} />
            ) : (
              <section className="playground">
              <div className="playground-topbar">
                <div>
                  <span className="eyebrow">Playground</span>
                  <h2>Build something with your Agent</h2>
                </div>
                <div className="session-info">
                  <span className="pulse" />
                  {selected.codexThreadId ? "Session connected" : "New session"}
                </div>
              </div>

              <div className="messages">
                {messages.length === 0 && !activeRun ? (
                  <div className="welcome">
                    <div className="welcome-orbit">
                      <div>⌁</div>
                    </div>
                    <h3>What should {selected.name} build?</h3>
                    <p>
                      The Agent can inspect files, write code, run commands, and continue the
                      same Codex session across messages.
                    </p>
                    <div className="prompt-grid">
                      {starterPrompts.map((item) => (
                        <button key={item} onClick={() => setPrompt(item)}>
                          <span>↗</span>
                          {item}
                        </button>
                      ))}
                    </div>
                  </div>
                ) : (
                  messages.map((message) => {
                    const read = readMessage(message.content);
                    // The journal is the record of what the boundary did. The reply is what the
                    // agent said about itself, and it is only read when the journal has not caught
                    // up with the run yet.
                    const verdict =
                      message.role === "assistant"
                        ? (verdictByRun.get(message.runId) ?? read.verdict)
                        : null;
                    return (
                      <article className={"message message-" + message.role} key={message.id}>
                        <div className="message-meta">
                          <strong>{message.role === "user" ? "You" : selected.name}</strong>
                          <span>{formatTime(message.createdAt)}</span>
                        </div>
                        <div className="message-body">
                          {message.role === "assistant" ? read.body : message.content}
                        </div>
                        {verdict && (
                          <p className={"turn-verdict tone-" + verdictTone(verdict.verdict)}>
                            <span className="verdict-dot" aria-hidden="true" />
                            {verdictSentence(verdict)}
                          </p>
                        )}
                      </article>
                    );
                  })
                )}
                {activeRun && ["queued", "running"].includes(activeRun.status) && (
                  <article className="message message-assistant thinking">
                    <div className="message-meta">
                      <strong>{selected.name}</strong>
                      <span>working in the Agent workspace</span>
                    </div>
                    <div className="thinking-row">
                      <Spinner />
                      Codex is reading, editing, or running commands…
                    </div>
                  </article>
                )}
                {activeRun?.status === "failed" && (
                  <article className="run-error">
                    <strong>Run failed</strong>
                    <span>{activeRun.error}</span>
                  </article>
                )}
                <div ref={messageEnd} />
              </div>

              <form className="composer" onSubmit={sendMessage}>
                <textarea
                  value={prompt}
                  onChange={(event) => setPrompt(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" && !event.shiftKey) {
                      event.preventDefault();
                      event.currentTarget.form?.requestSubmit();
                    }
                  }}
                  placeholder={
                    selected.status === "stopped"
                      ? "Start this Agent to continue…"
                      : "Describe what you want the Agent to do…"
                  }
                  disabled={
                    selected.status === "stopped" ||
                    selected.status === "busy" ||
                    activeRun != null && ["queued", "running"].includes(activeRun.status)
                  }
                  rows={3}
                />
                <div className="composer-footer">
                  <span>
                    Enter to send · Shift + Enter for newline · {system?.codexSandboxMode ?? "checking sandbox"}
                  </span>
                  <button
                    className="send-button"
                    disabled={
                      !prompt.trim() ||
                      selected.status === "stopped" ||
                      selected.status === "busy" ||
                      (activeRun != null && ["queued", "running"].includes(activeRun.status))
                    }
                    aria-label="Send message"
                  >
                    ↑
                  </button>
                </div>
              </form>
              </section>
            )}
          </>
        ) : (
          <div className="no-agent">
            <div className="no-agent-art">A</div>
            <span className="eyebrow">Agent Launchpad</span>
            <h1>Your runtime is ready for an Agent.</h1>
            <p>Create a workspace, give Codex a job, and continue the conversation here.</p>
            <button
              className="button button-primary"
              onClick={() => {
                setForm(emptyForm);
                setShowCreate(true);
              }}
            >
              Create your first Agent
            </button>
          </div>
        )}
      </main>

      {showCreate && (
        <div className="modal-backdrop" onMouseDown={() => setShowCreate(false)}>
          <form
            className="modal"
            onSubmit={createAgent}
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="modal-heading">
              <div>
                <span className="eyebrow">New workspace</span>
                <h2>Create an Agent</h2>
                <p>Each Agent gets a persistent folder and a resumable Codex session.</p>
              </div>
              <button type="button" onClick={() => setShowCreate(false)}>×</button>
            </div>
            <label>
              Name
              <input
                autoFocus
                placeholder="Frontend Builder"
                value={form.name}
                onChange={(event) => setForm({ ...form, name: event.target.value })}
                required
                maxLength={80}
              />
            </label>
            <label>
              Description
              <input
                placeholder="Builds polished React prototypes"
                value={form.description}
                onChange={(event) =>
                  setForm({ ...form, description: event.target.value })
                }
                maxLength={500}
              />
            </label>
            <label>
              Instructions
              <textarea
                value={form.instructions}
                onChange={(event) =>
                  setForm({ ...form, instructions: event.target.value })
                }
                rows={6}
                maxLength={10_000}
              />
            </label>
            <div className="modal-footer">
              <button
                type="button"
                className="button button-ghost"
                onClick={() => setShowCreate(false)}
              >
                Cancel
              </button>
              <button className="button button-primary" disabled={busy}>
                {busy ? <Spinner /> : "Create Agent"}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
