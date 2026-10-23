// The colourways graph.html knows. The palettes themselves live in the THEME block of src/html.js;
// this list is what the config key, the --colorway flag and the settings select validate against.
export const COLORWAYS = ['graphite-amber', 'signal', 'mono', 'mint'];
export const DEFAULT_COLORWAY = 'signal';

/** Returns the name when valid, else throws an Error that names the valid ones. */
export function checkColorway(name, where = 'colorway') {
  if (!COLORWAYS.includes(name)) throw new Error(`${where}: unknown colourway ${JSON.stringify(String(name)).slice(0, 60)} (expected ${COLORWAYS.join(', ')})`);
  return name;
}
