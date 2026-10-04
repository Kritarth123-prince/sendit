/**
 * Three-way merge for notepads (views/notepad.js).
 *
 * Several people (or devices) may type in the same notepad at once. Each editor remembers `base`,
 * the last text it knows is on the server. When someone else's save arrives (or a save of ours is
 * refused with 409 VERSION_CONFLICT), our edits since `base` are turned into patches and applied
 * onto their text with Google's diff-match-patch, which tolerates nearby changes (fuzzy matching).
 * Edits that cannot be placed are never dropped: they are appended in a clearly labelled block.
 *
 * Pure functions apart from loading the engine, so they are unit-tested in tests/js/notepad-merge.test.mjs.
 * @module features/notepad-merge
 */

let Engine = null;

/** The diff-match-patch engine, loaded on first use (assets/js/vendor/diff_match_patch.js). */
export async function loadEngine() {
  if (!Engine) Engine = (await import('../vendor/diff_match_patch.js')).diff_match_patch;
  return createEngine(Engine);
}

/** A configured engine instance from the diff_match_patch constructor. */
export function createEngine(Ctor) {
  const dmp = new Ctor();
  dmp.Diff_Timeout = 1;            // seconds; plenty for 1 MB of text, never freezes the tab for long
  dmp.Match_Threshold = 0.45;      // a little fuzzier than the default so nearby edits still land
  dmp.Match_Distance = 2000;
  dmp.Patch_DeleteThreshold = 0.5;
  dmp.Patch_Margin = 8;            // more context than the default 4: fewer misplaced patches
  return dmp;
}

/** Heading of the block that keeps edits which could not be merged. */
export const UNMERGED_HEADING = '— Your changes that could not be merged automatically —';

/**
 * Merge `mine` and `theirs`, both edited from `base`.
 * @returns {{text:string, clean:boolean, unmerged:string}} clean is false when some of our edits
 *   had to be appended as `unmerged` text instead of being placed.
 */
export function merge3(dmp, base, mine, theirs) {
  if (mine === base || mine === theirs) return { text: theirs, clean: true, unmerged: '' };
  if (theirs === base) return { text: mine, clean: true, unmerged: '' };
  const patches = dmp.patch_make(base, mine);
  const [text, applied] = dmp.patch_apply(patches, theirs);
  const lost = [];
  applied.forEach((ok, i) => {
    if (ok) return;
    const inserted = patches[i].diffs.filter((d) => d[0] === 1).map((d) => d[1]).join('');
    if (inserted.trim() !== '') lost.push(inserted);
  });
  if (!lost.length) return { text, clean: true, unmerged: '' };
  const unmerged = lost.join('\n');
  const sep = text === '' || text.endsWith('\n\n') ? '' : text.endsWith('\n') ? '\n' : '\n\n';
  return { text: text + sep + UNMERGED_HEADING + '\n' + unmerged + '\n', clean: false, unmerged };
}

/**
 * Where a caret position in `before` ends up in `after` (so a remote change does not move the
 * cursor of the person typing).
 */
export function mapOffset(dmp, before, after, offset) {
  if (before === after) return offset;
  if (offset <= 0) return 0;
  if (offset >= before.length) return after.length - (before.length - Math.min(offset, before.length));
  const diffs = dmp.diff_main(before, after, false);
  return Math.max(0, Math.min(after.length, dmp.diff_xIndex(diffs, offset)));
}

/** Words and characters for the footer (characters counted as the user sees them). */
export function countText(text) {
  const words = (text.match(/[\p{L}\p{N}][\p{L}\p{N}'’_-]*/gu) || []).length;
  const chars = Array.from(text).length;
  return { words, chars };
}

/** UTF-8 size in bytes (the 1 MB limit is in bytes). */
export function byteLength(text) {
  return new TextEncoder().encode(text).length;
}
