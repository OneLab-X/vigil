"use client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import * as React from "react";
import { Shell } from "@/components/shell";

export function Providers({ children }: { children: React.ReactNode }) {
  const [qc] = React.useState(() => new QueryClient({ defaultOptions: { queries: { staleTime: 10_000, retry: 1, refetchOnWindowFocus: false } } }));
  return <QueryClientProvider client={qc}><Shell>{children}</Shell></QueryClientProvider>;
}
