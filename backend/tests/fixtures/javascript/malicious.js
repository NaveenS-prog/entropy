// CANARY FILE: Under NO circumstances should this code be executed by the static analysis engine!
const fs = require('fs');

// Attempt canary side effect
try {
    fs.writeFileSync('/tmp/malicious_js_executed.txt', 'CANARY_EXECUTED');
} catch (e) {
    // canary ignore
}

// Exit canary
if (typeof process !== 'undefined' && process.exit) {
    process.exit(99);
}

function harmlessFunction() {
    return 123;
}

module.exports = { harmlessFunction };
