import { useEffect, useRef } from "react";

/**
 * Runs `task` now and then every `intervalMs`, and stops while the tab is hidden so a demo left
 * open in a background tab is not still polling. A live stream is a later lane; this is the
 * version that cannot desynchronise, because every tick asks the server what is true.
 */
export function usePolling(task: () => void | Promise<void>, intervalMs: number, enabled = true): void {
  const saved = useRef(task);
  saved.current = task;

  useEffect(() => {
    if (!enabled) return;
    let timer: number | undefined;
    let stopped = false;

    const tick = () => {
      if (stopped || document.hidden) return;
      void saved.current();
    };

    const start = () => {
      window.clearInterval(timer);
      timer = window.setInterval(tick, intervalMs);
    };

    const onVisibility = () => {
      if (document.hidden) {
        window.clearInterval(timer);
        return;
      }
      tick();
      start();
    };

    tick();
    start();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      stopped = true;
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [enabled, intervalMs]);
}
