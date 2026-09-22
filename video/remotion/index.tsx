import React, { useEffect, useMemo, useState } from 'react';
import { AbsoluteFill, Audio, Composition, Easing, Video, interpolate, registerRoot, spring, staticFile, useCurrentFrame, useVideoConfig } from 'remotion';
import { z } from 'zod';
import effectsJson from '../effects.json';
import { EffectsSchema, type Clip, type Effect, type Segment } from './types';
import './styles.css';

const effects = EffectsSchema.parse(effectsJson);
const captionSchema = z.object({ captions: z.array(z.object({ seq: z.number(), text: z.string() })) });

type Sidecar = z.infer<typeof captionSchema>;

function loadSidecar(): Sidecar | null {
  return null;
}

function Badge({ label }: { label: Clip['label'] }) {
  const colors = { LIVE: '#ef806f', REPLAY: '#dbb967', MOCK: '#65d7bd' };
  return <div className="badge" style={{ borderColor: colors[label], color: colors[label] }}>{label}</div>;
}

function segmentAt(segments: Segment[], seconds: number): Segment {
  return segments.find((segment) => seconds >= segment.start && seconds < segment.end) ?? segments[segments.length - 1];
}

function Active({ effect, frame }: { effect: Effect; frame: number }) {
  return effect.type !== 'titleCard' && frame >= effect.t0 * 30 && frame <= effect.t1 * 30;
}

function zoomTransform(effect: Extract<Effect, { type: 'zoom' }>, frame: number) {
  const start = effect.t0 * 30;
  const end = effect.t1 * 30;
  const progress = spring({ frame: frame - start, fps: 30, config: { damping: 200 }, durationInFrames: Math.max(1, end - start) });
  const eased = interpolate(progress, [0, 1], [0, 1], { easing: Easing.inOut(Easing.cubic), extrapolateLeft: 'clamp', extrapolateRight: 'clamp' });
  const scale = interpolate(eased, [0, 1], [1, effect.scale]);
  const originX = `${effect.x * 100}%`;
  const originY = `${effect.y * 100}%`;
  return { transform: `scale(${scale})`, transformOrigin: `${originX} ${originY}` };
}

function Highlight({ effect }: { effect: Extract<Effect, { type: 'highlight' }> }) {
  return <div className="highlight" style={{ left: `${effect.x * 100}%`, top: `${effect.y * 100}%`, width: `${effect.w * 100}%`, height: `${effect.h * 100}%` }}><span>{effect.text}</span></div>;
}

function Callout({ effect }: { effect: Extract<Effect, { type: 'callout' }> }) {
  return <div className="callout" style={{ left: `${effect.x * 100}%`, top: `${effect.y * 100}%` }}><span className="callout-dot" />{effect.text}</div>;
}

function Caption({ effect }: { effect: Extract<Effect, { type: 'caption' }> }) {
  return <div className="effect-caption">{effect.text}</div>;
}

function TitleCard({ effect, frame }: { effect: Extract<Effect, { type: 'titleCard' }>; frame: number }) {
  const duration = effect.duration * 30;
  const opacity = interpolate(frame, [0, 12, duration - 12, duration], [0, 1, 1, 0], { extrapolateRight: 'clamp', extrapolateLeft: 'clamp' });
  return <AbsoluteFill className="title-card" style={{ opacity }}><div>{effect.text}</div></AbsoluteFill>;
}

function SidecarCaption({ frame }: { frame: number }) {
  const [sidecar, setSidecar] = useState<Sidecar | null>(loadSidecar());
  useEffect(() => {
    fetch(staticFile('video-captions.example.json'))
      .then((response) => response.json())
      .then((value) => setSidecar(captionSchema.parse(value)))
      .catch(() => undefined);
  }, []);
  const current = useMemo(() => sidecar?.captions.filter((caption) => caption.seq <= Math.floor(frame / 30)).at(-1), [frame, sidecar]);
  return current ? <div className="sidecar-caption">{current.text}</div> : null;
}

function ClipView({ clip }: { clip: Clip }) {
  const frame = useCurrentFrame();
  const { durationInFrames } = useVideoConfig();
  const label = segmentAt(effects.segments, frame / effects.fps).label;
  const activeEffects = clip.effects.filter((effect) => Active({ effect, frame }));
  const zoom = [...clip.effects].reverse().find((effect): effect is Extract<Effect, { type: 'zoom' }> => effect.type === 'zoom' && Active({ effect, frame }));
  const title = clip.effects.find((effect): effect is Extract<Effect, { type: 'titleCard' }> => effect.type === 'titleCard' && frame < effect.duration * 30);
  return <AbsoluteFill className="studio">
    <div className="window-shadow" />
    <div className="window">
      <div className="window-bar"><span /><span /><span /><small>SENTINEL / TRACE EVIDENCE</small></div>
      <div className="media"><Video src={staticFile(clip.file)} muted={Boolean(effects.voiceover)} className="source-video" style={zoom ? zoomTransform(zoom, frame) : undefined} /></div>
    </div>
    <Badge label={label} />
    <div className="film-note">POLISH LAYER / SOURCE FOOTAGE UNCHANGED</div>
    {activeEffects.map((effect, index) => {
      if (effect.type === 'zoom') return null;
      if (effect.type === 'highlight') return <Highlight key={index} effect={effect} />;
      if (effect.type === 'callout') return <Callout key={index} effect={effect} />;
      if (effect.type === 'caption') return <Caption key={index} effect={effect} />;
      return null;
    })}
    <SidecarCaption frame={frame} />
    {title ? <TitleCard effect={title} frame={frame} /> : null}
    {clip.effects.some((effect) => effect.type === 'titleCard' && frame >= durationInFrames - effect.duration * 30) ? <div className="outro-vignette" /> : null}
    {effects.voiceover ? <Audio src={staticFile(effects.voiceover)} /> : null}
  </AbsoluteFill>;
}

export const RemotionRoot: React.FC = () => <>
  <Composition id="SentinelPolish" component={ClipView} durationInFrames={effects.duration * effects.fps} fps={effects.fps} width={effects.width} height={effects.height} defaultProps={{ clip: effects.clips[0] }} schema={z.object({ clip: z.any() })} />
</>;

registerRoot(() => <RemotionRoot />);

export default RemotionRoot;
