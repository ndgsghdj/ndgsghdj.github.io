const CATPPUCCIN_MOCHA_COLORS: Record<string, string> = {
  rosewater: '#f5e0dc',
  flamingo: '#f2cdcd',
  pink: '#f5c2e7',
  mauve: '#cba6f7',
  red: '#f38ba8',
  maroon: '#eba0ac',
  peach: '#fab387',
  yellow: '#f9e2af',
  green: '#a6e3a1',
  teal: '#94e2d5',
  sky: '#89dceb',
  sapphire: '#74c7ec',
  blue: '#89b4fa',
  lavender: '#b4befe',
  text: '#cdd6f4',
  subtext1: '#bac2de',
  subtext0: '#a6adc8',
  overlay2: '#9399b2',
  overlay1: '#7f849c',
  overlay0: '#6c7086',
  surface2: '#585b70',
  surface1: '#45475a',
  surface0: '#313244',
  base: '#1e1e2e',
  mantle: '#181825',
  crust: '#11111b',
};

const hexColorRegex = /^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/;

export function resolveColorToken(source: string): string {
  const value = source.trim();
  if (!value) {
    throw new Error('Missing color value.');
  }

  const normalized = value.toLowerCase();
  if (Object.prototype.hasOwnProperty.call(CATPPUCCIN_MOCHA_COLORS, normalized)) {
    return CATPPUCCIN_MOCHA_COLORS[normalized];
  }

  if (hexColorRegex.test(value)) {
    return value;
  }

  throw new Error(
    `Unsupported color '${source}'. Use a Catppuccin alias or a hex code like #fab387.`,
  );
}
