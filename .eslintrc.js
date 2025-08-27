/**
 * 🔐 ENTERPRISE ESLint SECURITY CONFIGURATION
 * Comprehensive linting rules focused on security and code quality
 */

module.exports = {
  env: {
    browser: true,
    commonjs: true,
    es2021: true,
    node: true,
    mocha: true
  },
  extends: [
    'eslint:recommended',
    'plugin:security/recommended'
  ],
  plugins: [
    'security',
    'no-secrets',
    'no-unsanitized'
  ],
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module'
  },
  rules: {
    // 🚨 CRITICAL SECURITY RULES
    'security/detect-buffer-noassert': 'error',
    'security/detect-child-process': 'warn',
    'security/detect-disable-mustache-escape': 'error',
    'security/detect-eval-with-expression': 'error',
    'security/detect-new-buffer': 'error',
    'security/detect-no-csrf-before-method-override': 'error',
    'security/detect-non-literal-fs-filename': 'warn',
    'security/detect-non-literal-regexp': 'warn',
    'security/detect-non-literal-require': 'warn',
    'security/detect-object-injection': 'error',
    'security/detect-possible-timing-attacks': 'error',
    'security/detect-pseudoRandomBytes': 'error',
    'security/detect-unsafe-regex': 'error',
    'security/detect-bidi-characters': 'error',

    // 🔐 SECRETS AND SENSITIVE DATA
    'no-secrets/no-secrets': ['error', {
      'tolerance': 4.2,
      'ignoreContent': ['^AAAA', '^sha256/', 'test-', 'mock-', 'example-'],
      'ignoreIdentifiers': ['EXAMPLE', 'TEST', 'MOCK', 'DEMO']
    }],

    // 🧼 XSS AND INJECTION PREVENTION
    'no-unsanitized/method': 'error',
    'no-unsanitized/property': 'error',

    // 💡 GENERAL SECURITY BEST PRACTICES
    'no-eval': 'error',
    'no-implied-eval': 'error',
    'no-new-func': 'error',
    'no-script-url': 'error',
    'no-proto': 'error',
    'no-extend-native': 'error',
    'no-global-assign': 'error',
    'no-implicit-globals': 'error',

    // 🛡️ CRYPTO AND HASH SECURITY
    'prefer-const': 'error',
    'no-var': 'error',
    'no-delete-var': 'error',

    // 🔍 ERROR HANDLING
    'handle-callback-err': 'error',
    'no-process-exit': 'warn',
    'no-process-env': 'off', // We need process.env for config

    // 📊 CODE QUALITY
    'no-unused-vars': ['error', { 
      'argsIgnorePattern': '^_',
      'varsIgnorePattern': '^_'
    }],
    'no-undef': 'error',
    'no-redeclare': 'error',
    'no-dupe-keys': 'error',
    'no-duplicate-case': 'error',
    'no-empty': 'error',
    'no-extra-semi': 'error',
    'no-func-assign': 'error',
    'no-invalid-regexp': 'error',
    'no-irregular-whitespace': 'error',
    'no-sparse-arrays': 'error',
    'no-unreachable': 'error',
    'use-isnan': 'error',
    'valid-typeof': 'error',

    // 🎯 SPECIFIC RULES FOR OUR CODEBASE
    'curly': 'error',
    'dot-notation': 'error',
    'eqeqeq': ['error', 'always'],
    'no-alert': 'error',
    'no-caller': 'error',
    'no-constructor-return': 'error',
    'no-else-return': 'warn',
    'no-empty-function': 'warn',
    'no-floating-decimal': 'error',
    'no-lone-blocks': 'error',
    'no-multi-spaces': 'error',
    'no-new': 'error',
    'no-new-wrappers': 'error',
    'no-return-assign': 'error',
    'no-self-assign': 'error',
    'no-self-compare': 'error',
    'no-sequences': 'error',
    'no-throw-literal': 'error',
    'no-unmodified-loop-condition': 'error',
    'no-unused-expressions': 'error',
    'no-useless-call': 'error',
    'no-useless-concat': 'error',
    'no-useless-return': 'error',
    'prefer-promise-reject-errors': 'error',
    'radix': 'error',
    'yoda': 'error',

    // 📏 STYLE AND FORMATTING (Security-relevant)
    'brace-style': ['error', '1tbs'],
    'comma-dangle': ['error', 'never'],
    'comma-spacing': 'error',
    'comma-style': 'error',
    'computed-property-spacing': 'error',
    'eol-last': 'error',
    'func-call-spacing': 'error',
    'indent': ['error', 2, { 'SwitchCase': 1 }],
    'key-spacing': 'error',
    'keyword-spacing': 'error',
    'linebreak-style': ['error', 'unix'],
    'no-mixed-spaces-and-tabs': 'error',
    'no-multiple-empty-lines': ['error', { 'max': 2 }],
    'no-trailing-spaces': 'error',
    'object-curly-spacing': ['error', 'always'],
    'quotes': ['error', 'single', { 'avoidEscape': true }],
    'semi': ['error', 'always'],
    'semi-spacing': 'error',
    'space-before-blocks': 'error',
    'space-before-function-paren': ['error', { 
      'anonymous': 'never',
      'named': 'never',
      'asyncArrow': 'always'
    }],
    'space-in-parens': 'error',
    'space-infix-ops': 'error',
    'space-unary-ops': 'error',
    'spaced-comment': 'error'
  },
  overrides: [
    {
      // 🧪 TEST FILE SPECIFIC RULES
      files: ['tests/**/*.js', '**/*.test.js'],
      rules: {
        'no-unused-expressions': 'off', // Allow chai assertions
        'security/detect-non-literal-fs-filename': 'off', // Tests need file operations
        'no-secrets/no-secrets': 'off', // Tests may contain test secrets
        'security/detect-child-process': 'off' // Tests may spawn processes
      }
    },
    {
      // 🔧 CONFIG FILE SPECIFIC RULES  
      files: ['.eslintrc.js', 'jest.config.js', 'mocha.config.js'],
      rules: {
        'no-undef': 'off'
      }
    }
  ],
  globals: {
    // 🧪 TEST GLOBALS
    'describe': 'readonly',
    'it': 'readonly',
    'before': 'readonly',
    'after': 'readonly',
    'beforeEach': 'readonly',
    'afterEach': 'readonly',
    'expect': 'readonly',
    'sinon': 'readonly',
    
    // 🧪 CUSTOM TEST UTILITIES
    'TestDataGenerator': 'readonly',
    'TestUtils': 'readonly',
    'SecurityTestHelpers': 'readonly',
    'PerformanceTestUtils': 'readonly',
    'TEST_CONFIG': 'readonly',
    'TEST_RESPONSES': 'readonly'
  },
  ignorePatterns: [
    'node_modules/',
    'dist/',
    'build/',
    '*.min.js',
    'coverage/',
    '.nyc_output/',
    'android/',
    'assets/',
    '*.apk'
  ]
};