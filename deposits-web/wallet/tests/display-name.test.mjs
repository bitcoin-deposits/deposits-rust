// Cross-impl pin for the pubkey display-name convention.
//
// Mirrors deposits-protocol/src/display_name.rs `cross_impl_vectors` —
// if these vectors change, change BOTH sides in the same commit.

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { sha256 } from '../vendor/noble-hashes-sha256.js';
import { WORDLIST } from '../vendor/bip39-english.js';

function hexToBytes(h) {
  return new Uint8Array(h.match(/.{2}/g).map((b) => parseInt(b, 16)));
}

// Same algorithm as index.html's pubkeyDisplayName (kept in sync by eye;
// the binding constraint is the pinned vectors below).
function pubkeyDisplayName(pubkeyHex) {
  const hash = sha256(hexToBytes(pubkeyHex));
  const words = [];
  for (let w = 0; w < 4; w++) {
    let idx = 0;
    for (let b = 0; b < 11; b++) {
      const bit = w * 11 + b;
      idx = (idx << 1) | ((hash[bit >> 3] >> (7 - (bit & 7))) & 1);
    }
    words.push(WORDLIST[idx]);
  }
  return words.join('-');
}

test('display name matches rust pin: 0x02*33', () => {
  assert.equal(pubkeyDisplayName('02'.repeat(33)), 'left-kingdom-divide-chuckle');
});

test('display name matches rust pin: secp generator', () => {
  assert.equal(
    pubkeyDisplayName('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
    'author-member-type-ritual',
  );
});
