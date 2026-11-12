import { test } from 'node:test';
import assert from 'node:assert/strict';
import { lighten, lightRgb } from '../public/js/theme.js';

const lum = ([r, g, b]) => { const l = (c) => { c /= 255; return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4; }; return 0.2126 * l(r) + 0.7152 * l(g) + 0.0722 * l(b); };
const contrast = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };
const rgb = (hex) => [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16));
const PAPER = lightRgb([3, 13, 8]);   // the dark ground, as the light theme draws it

test('the night ground becomes pale paper and pale ink becomes dark ink', () => {
  assert.ok(lum(PAPER) > 0.85);
  assert.ok(contrast(lightRgb(rgb('#e3efe8')), PAPER) > 12);
  assert.ok(contrast(lightRgb([255, 255, 255]), PAPER) > 14);
});

test('accents keep their colour and can be read on the paper', () => {
  for (const hex of ['#ff5a4f', '#6fe3b0', '#8ec5ff', '#f0b45a', '#f6e016']) {
    const [r, g, b] = lightRgb(rgb(hex));
    assert.ok(Math.max(r, g, b) - Math.min(r, g, b) > 60, `${hex} kept its colour`);
    assert.ok(contrast([r, g, b], PAPER) > 3, `${hex} readable`);
  }
  // red stays red, green stays green
  const red = lightRgb(rgb('#ff5a4f')), green = lightRgb(rgb('#6fe3b0'));
  assert.ok(red[0] > red[1] && red[0] > red[2]);
  assert.ok(green[1] > green[0] && green[1] > green[2]);
});

test('lighten rewrites only colours, in any form, and leaves the rest alone', () => {
  assert.match(lighten('#fff'), /^#[0-9a-f]{6}$/);
  assert.match(lighten('rgba(0,0,0,.7)'), /^rgba\(\d+,\d+,\d+,\.7\)$/);
  assert.match(lighten('#ff000080'), /80$/);
  assert.equal(lighten('url(#fade)'), 'url(#fade)');
  assert.equal(lighten('white-space:nowrap'), 'white-space:nowrap');
  assert.match(lighten('color:white'), /^color:#[0-9a-f]{6}$/);
  assert.equal(lighten('none'), 'none');
  assert.equal(lighten(12), 12);
});
