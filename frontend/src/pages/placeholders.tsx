import { GitCompare } from "lucide-react";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/layout/PageHeader";

// Scaffold pages. Each is replaced as its roadmap milestone lands (CLAUDE.md §15).

export function ComparePage() {
  return (
    <>
      <PageHeader title="Retest / compare" />
      <EmptyState
        icon={GitCompare}
        title="Nothing to compare"
        description="Run at least two scans of the same target to compare results."
      />
    </>
  );
}
