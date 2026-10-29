// The colourways graph.html knows. The palettes themselves live in the THEME block of src/html.js;
// this list is what the config key, the --colorway flag and the settings select validate against.
export const COLORWAYS = ['graphite-amber', 'signal', 'mono', 'mint', 'ember'];
export const DEFAULT_COLORWAY = 'signal';
/** Default for a Firebase project when nothing picks one: the same black-and-grid look in orange and yellow. */
export const FIREBASE_COLORWAY = 'ember';

/** The colourway a page opens in: an explicit choice, else the platform's default. */
export const defaultColorway = (platform) => (platform === 'firebase' ? FIREBASE_COLORWAY : DEFAULT_COLORWAY);

/** Returns the name when valid, else throws an Error that names the valid ones. */
export function checkColorway(name, where = 'colorway') {
  if (!COLORWAYS.includes(name)) throw new Error(`${where}: unknown colourway ${JSON.stringify(String(name)).slice(0, 60)} (expected ${COLORWAYS.join(', ')})`);
  return name;
}
