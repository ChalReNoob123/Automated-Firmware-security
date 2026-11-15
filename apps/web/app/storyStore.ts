import { create } from 'zustand';

// Scroll position of the pinned story stage (0..1), shared with the WebGL
// scene without re-rendering React — useFrame reads it via getState().
// Round 17 adds `dragging`: the drag-to-orbit state, read by the WebGL scene
// (to pause ambient drift while the ensemble is grabbed) and by the cursor
// (to flip its contextual label to ORBIT) without per-frame React renders.
type StoryState = {
  p: number;
  setP: (v: number) => void;
  dragging: boolean;
  setDragging: (v: boolean) => void;
};

export const useStory = create<StoryState>()((set) => ({
  p: 0,
  setP: (p) => set({ p }),
  dragging: false,
  setDragging: (dragging) => set({ dragging }),
}));

export const seg = (p: number, a: number, b: number) => Math.min(1, Math.max(0, (p - a) / (b - a)));
