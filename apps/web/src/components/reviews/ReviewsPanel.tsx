import { ReviewCard } from "./ReviewCard";
import type { Agent, Review } from "../../types";

/**
 * The review queue: every turn the boundary stopped for a human, newest first. A settled turn
 * leaves this screen and reads back in the run timeline of the agent that produced it.
 */
export function ReviewsPanel({
  reviews,
  agents,
  settling,
  onApprove,
  onReject,
  onOpenAgent,
}: {
  reviews: Review[];
  agents: Agent[];
  settling: string | null;
  onApprove: (review: Review) => void;
  onReject: (review: Review) => void;
  onOpenAgent: (agentId: string) => void;
}) {
  const nameOf = (agentId: string) => agents.find((agent) => agent.id === agentId)?.name ?? "Unknown agent";

  return (
    <section className="reviews">
      <header className="reviews-topbar">
        <div>
          <span className="eyebrow">Review queue</span>
          <h2>Proposed changes waiting for a human</h2>
          <p className="reviews-lede">
            Each of these turns has already run against a sealed copy of its workspace. Nothing below has touched the
            real workspace, and nothing will until it is approved here.
          </p>
        </div>
        <div className="reviews-aside">
          <span className="reviews-count">
            {reviews.length} <span>waiting</span>
          </span>
          <p className="actor-note">
            Decisions are recorded against the principal the server authenticated, not a name typed
            here. On loopback that is <code>operator</code>; behind a token it is a stable name
            derived from the token that was actually presented.
          </p>
        </div>
      </header>

      {reviews.length === 0 ? (
        <div className="reviews-empty">
          <div className="reviews-empty-mark" aria-hidden="true">
            ◇
          </div>
          <h3>No proposed changes waiting</h3>
          <p>
            Clean turns commit on their own and violating turns are discarded on their own. A turn arrives here only
            when a rule asks for a person, which is meant to be rare.
          </p>
        </div>
      ) : (
        <div className="review-list">
          {reviews.map((review) => (
            <div key={review.runId}>
              <ReviewCard
                review={review}
                agentName={nameOf(review.agentId)}
                busy={settling === review.runId}
                onApprove={onApprove}
                onReject={onReject}
              />
              <button className="review-jump" onClick={() => onOpenAgent(review.agentId)}>
                Open {nameOf(review.agentId)} and its run timeline
              </button>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
