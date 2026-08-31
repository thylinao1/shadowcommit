/**
 * Every agent on this platform runs inside a transaction, with no per-agent configuration. The
 * badge is the visible half of that claim, so it says so on the agent rather than in a settings
 * page nobody opens.
 */
export function TransactionsBadge({ compact = false }: { compact?: boolean }) {
  if (compact) {
    return (
      <span className="tx-badge tx-compact" title="Transactions: ON (default)">
        <span className="tx-dot" aria-hidden="true" />
        <span className="visually-hidden">Transactions: ON (default)</span>
        TX
      </span>
    );
  }
  return (
    <span className="tx-badge">
      <span className="tx-dot" aria-hidden="true" />
      Transactions: ON (default)
    </span>
  );
}
