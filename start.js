#!/usr/bin/env node

require('./src/smartcache');

try {
  require('open')('http://localhost:3000');
} catch (err) {
  console.log('Dashboard disponibile su http://localhost:3000');
}