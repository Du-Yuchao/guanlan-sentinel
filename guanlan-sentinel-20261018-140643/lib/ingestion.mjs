import { hash, normalize } from './intelligence.mjs';

// The first observation belongs to the database, not to an upstream payload.
// Replaying a bundled snapshot must not overwrite a newer live observation.
export function mergeObservation(prior, incoming, { mode, runId, at, verifiedSnapshot }) {
  const replayLive = prior?.dataMode === 'live' && mode === 'demo';
  if (replayLive && !verifiedSnapshot) return { ...prior, replayedAt: at };
  const merged = replayLive ? { ...prior } : { ...prior, ...incoming };
  const useSnapshot = verifiedSnapshot?.verifiedAt && (!prior?.verifiedAt || !Number.isFinite(Date.parse(prior.verifiedAt)) || Date.parse(verifiedSnapshot.verifiedAt) >= Date.parse(prior.verifiedAt));
  const verified = useSnapshot ? normalize({ ...verifiedSnapshot, dataMode: 'snapshot' }, at) : prior?.verifiedAt ? prior : null;
  if ((mode === 'live' || replayLive) && verified) {
    for (const field of ['title', 'summary', 'affected', 'fixed', 'remediation', 'ranges', 'relatedIds']) {
      if (verified[field] !== undefined) merged[field] = verified[field];
    }
    merged.verifiedAt = verified.verifiedAt;
    if (mode === 'live') {
      merged.liveSummary = incoming.summary;
      merged.liveAffected = incoming.affected;
      merged.liveFixed = incoming.fixed;
      merged.livePublished = incoming.published;
    }
    merged.reviewNote = `保留 ${verified.verifiedAt} 核验的摘要与版本结论；实时原文另存于证据中，更新结论仍需复核。`;
    const evidence = [...(useSnapshot ? verified.evidence : []), ...(prior?.evidence ?? []).filter(e => e.snapshot || e.mode === 'snapshot' || e.kind === 'paraphrase'), ...((replayLive ? prior : incoming).evidence ?? [])];
    merged.evidence = [...new Map(evidence.map(e => [`${e.url}:${e.hash}`, e])).values()].slice(-40);
    merged.tags = [...new Set([...(verified.tags ?? []), ...(prior?.tags ?? []), ...(incoming.tags ?? [])])];
  }
  if(merged.enrichment) merged.enrichment={...merged.enrichment,versionRanges:merged.ranges ?? [],remediation:merged.remediation,evidenceIntegrity:(merged.evidence ?? []).every(e=>e.hash===hash(e.excerpt))};
  merged.contentHash = hash({ title: merged.title, summary: merged.summary, url: merged.url, evidence: (merged.evidence ?? []).map(e => e.hash) });
  if (replayLive) return { ...merged, replayedAt: at };
  merged.firstSeenAt = prior?.firstSeenAt ?? prior?.collectedAt ?? at;
  merged.firstSeenMode = prior?.firstSeenMode ?? (prior ? prior.dataMode ?? 'snapshot' : incoming.dataMode ?? (mode === 'live' ? 'live' : 'snapshot'));
  merged.discoveryRunId = prior?.discoveryRunId ?? (prior ? null : runId);
  merged.lastSeenAt = at;
  if (mode === 'live') {
    merged.firstLiveAt = prior?.firstLiveAt ?? at;
    merged.lastLiveAt = at;
    merged.lastLiveRunId = runId;
  }
  return merged;
}
