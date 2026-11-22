import { useEffect, useState } from "react";
import { api } from "./api";
import type { RuleInfo } from "./types";

let cache: Promise<Map<string, RuleInfo>> | null = null;

function load(): Promise<Map<string, RuleInfo>> {
  cache ??= api
    .rules()
    .then((rules) => new Map(rules.map((r) => [r.id, r])))
    .catch((err: unknown) => {
      cache = null; // allow a later retry
      throw err;
    });
  return cache;
}

/** Rule catalogue (descriptions for "Why it matters"). `null` while loading or on error. */
export function useRules(): Map<string, RuleInfo> | null {
  const [rules, setRules] = useState<Map<string, RuleInfo> | null>(null);
  useEffect(() => {
    let alive = true;
    load()
      .then((r) => {
        if (alive) setRules(r);
      })
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, []);
  return rules;
}

/** Test hook: drop the module cache. */
export function resetRulesCache(): void {
  cache = null;
}
