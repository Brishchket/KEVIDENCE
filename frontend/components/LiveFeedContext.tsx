"use client";
/**
 * LiveFeedContext.tsx — App-wide singleton SSE connection.
 *
 * Provides connectionState and recentEvents to any component via context,
 * so we only ever open one SSE connection per page load regardless of how
 * many components subscribe.
 *
 * Usage:
 *   Wrap your app in <LiveFeedProvider>
 *   Then consume: const { connectionState, recentEvents } = useLiveFeedContext()
 */

import React, {
  createContext,
  useCallback,
  useContext,
  useState,
} from "react";
import { useLiveFeed, ConnectionState, LiveEvent } from "@/lib/useLiveFeed";

interface LiveFeedContextValue {
  connectionState: ConnectionState;
  recentEvents: LiveEvent[];
  lastEventId: number;
}

const LiveFeedContext = createContext<LiveFeedContextValue>({
  connectionState: "reconnecting",
  recentEvents: [],
  lastEventId: 0,
});

export function LiveFeedProvider({ children }: { children: React.ReactNode }) {
  const [recentEvents, setRecentEvents] = useState<LiveEvent[]>([]);

  const handleEvent = useCallback((ev: LiveEvent) => {
    setRecentEvents((prev) => [ev, ...prev].slice(0, 50));
  }, []);

  const { connectionState, lastEventId } = useLiveFeed({ onEvent: handleEvent });

  return (
    <LiveFeedContext.Provider value={{ connectionState, recentEvents, lastEventId }}>
      {children}
    </LiveFeedContext.Provider>
  );
}

export function useLiveFeedContext(): LiveFeedContextValue {
  return useContext(LiveFeedContext);
}
