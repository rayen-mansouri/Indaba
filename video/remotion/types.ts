import { z } from 'zod';

export const BadgeSchema = z.enum(['LIVE', 'REPLAY', 'MOCK']);
export const SegmentSchema = z.object({ start: z.number().nonnegative(), end: z.number().positive(), label: BadgeSchema }).refine((v) => v.end > v.start, 'segment end must be greater than start');
const Range = z.object({ t0: z.number().nonnegative(), t1: z.number().nonnegative() }).refine((v) => v.t1 > v.t0, 't1 must be greater than t0');

const RangeSchema = z.object({
  t0: z.number().nonnegative(),
  t1: z.number().nonnegative(),
}).refine((v) => v.t1 > v.t0, 't1 must be greater than t0');

const ZoomEffectSchema = RangeSchema.extend({
  type: z.literal('zoom'),
  x: z.number().min(0).max(1),
  y: z.number().min(0).max(1),
  scale: z.number().min(1).max(2.5),
});

const HighlightEffectSchema = RangeSchema.extend({
  type: z.literal('highlight'),
  x: z.number().min(0).max(1),
  y: z.number().min(0).max(1),
  w: z.number().positive().max(1),
  h: z.number().positive().max(1),
  text: z.string().optional(),
});

const CalloutEffectSchema = RangeSchema.extend({
  type: z.literal('callout'),
  x: z.number().min(0).max(1),
  y: z.number().min(0).max(1),
  text: z.string().min(1),
});

const CaptionEffectSchema = RangeSchema.extend({
  type: z.literal('caption'),
  text: z.string().min(1),
});

const TitleCardEffectSchema = z.object({
  type: z.literal('titleCard'),
  text: z.string().min(1),
  duration: z.number().positive(),
});

export const EffectSchema = z.union([
  ZoomEffectSchema,
  HighlightEffectSchema,
  CalloutEffectSchema,
  CaptionEffectSchema,
  TitleCardEffectSchema,
]);

export const ClipSchema = z.object({
  file: z.string().min(1),
  label: BadgeSchema,
  effects: z.array(EffectSchema)
});

export const EffectsSchema = z.object({
  fps: z.literal(30),
  width: z.literal(1920),
  height: z.literal(1080),
  duration: z.number().positive(),
  voiceover: z.string().optional(),
  segments: z.array(SegmentSchema).min(1),
  clips: z.array(ClipSchema).min(1)
});

export type Effect = z.infer<typeof EffectSchema>;
export type Clip = z.infer<typeof ClipSchema>;
export type Effects = z.infer<typeof EffectsSchema>;
export type Segment = z.infer<typeof SegmentSchema>;
