// Catches names that are used but never defined (a missing helper only fails when that screen draws, so tests miss it).
// Deliberately narrow: correctness, not style.
import globals from 'globals';

export default [
  { ignores: ['node_modules/**', 'bench/**'] },
  { files: ['public/js/**/*.js'], languageOptions: { ecmaVersion: 2024, sourceType: 'module', globals: globals.browser }, rules: { 'no-undef': 'error' } },
  { files: ['src/**/*.js', 'scripts/**/*.{js,mjs}', 'test/**/*.js', 'eslint.config.js'], languageOptions: { ecmaVersion: 2024, sourceType: 'module', globals: globals.node }, rules: { 'no-undef': 'error' } },
];
