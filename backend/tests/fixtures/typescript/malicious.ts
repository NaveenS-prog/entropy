// CANARY FILE: TypeScript malicious payload - MUST NOT EXECUTE
import * as fs from 'fs';

// Try side-effect write
try {
    fs.writeFileSync('/tmp/malicious_ts_executed.txt', 'CANARY_TS_EXECUTED');
} catch (e) {
    // canary ignore
}

// Try process exit
if (typeof process !== 'undefined' && process.exit) {
    process.exit(98);
}

export function sampleSafeCode(): number {
    return 42;
}
