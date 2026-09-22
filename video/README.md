# SENTINEL demonstration video

## Final deliverables

- [Final film](out/sentinel_demo_polished.mp4) — 7:00, 1920×1080, 30 fps, H.264/AAC.
- [Captions](out/sentinel_demo.srt).
- [Thumbnail](out/thumbnail.png).

The film uses only synthetic simulator data. It labels live Qwen3-8B, mock-model,
and replay material separately. The paired invoice control reaches the attack under
`allow_all`; the protected Qwen run blocks the unauthorised tool request but retains
its evaluator-reported utility limitation. Replays and team-authored probes are not
presented as live Qwen evidence.

## Rebuild the polish layer

The committed Remotion source preserves the reviewable overlay configuration without
including temporary browsers, node modules, raw captures, local speech files, model
assets, or build tools.

```powershell
cd video
npm ci
npm run validate
npm run typecheck
npm run render
```

The source footage is `out/sentinel_demo_no_subtitles.mp4`; it already contains the
real viewer capture and its original audio. `effects.json` may only add labels,
captions, callouts, highlights, and zooms. It must not change trace text, reorder
events, hide an outcome, or fabricate evidence. The final render is written to
`out/sentinel_demo_polished.mp4`.

## Review checklist

- The four required beats appear in order: benign completion, attack reachability,
  firewall decision, and secure outcome.
- The paired invoice attack shows `attack_success=true` for the control and
  `attack_success=false` for SENTINEL, with the protected run's utility failure
  visible rather than edited away.
- The invoice block overlay says `G2_TASK_SCOPE: TASK_CAPABILITY_DENIED`, matching
  its actual trace; it does not claim a G1 failure.
- The technical report, evidence manifest, viewer, and captions remain the
  authoritative companions to the film.
