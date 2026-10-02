// Circular dependency B -> A
const a = require('./architecture_a');

function serviceB() {
    return 42;
}

module.exports = { serviceB };
