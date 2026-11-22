import { GitCompare, ListChecks, Play, Server } from "lucide-react";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/layout/PageHeader";
import { Button } from "@/components/ui/button";

// Scaffold pages. Each is replaced as its roadmap milestone lands (CLAUDE.md §15).

export function TargetsPage() {
  return (
    <>
      <PageHeader title="Targets" description="Hosts you have authorization to scan." />
      <EmptyState
        icon={Server}
        title="No targets yet"
        description="Add a host you own or have written permission to test. Runtime probes only run against confirmed targets."
        action={<Button disabled>Add target</Button>}
      />
    </>
  );
}

export function NewScanPage() {
  return (
    <>
      <PageHeader
        title="New scan"
        description="Analyze an OpenAPI spec, an Nginx config, or a live API."
      />
      <EmptyState
        icon={Play}
        title="Scanning is not available yet"
        description="Static analysis arrives in the next milestone."
      />
    </>
  );
}

export function FindingsPage() {
  return (
    <>
      <PageHeader title="Findings" />
      <EmptyState
        icon={ListChecks}
        title="No findings"
        description="Run a scan to see findings here."
      />
    </>
  );
}

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
