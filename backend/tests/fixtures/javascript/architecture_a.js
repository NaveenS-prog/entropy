// Circular dependency A -> B
const b = require('./architecture_b');

function serviceA() {
    return b.serviceB() + 1;
}

module.exports = { serviceA };
