const fastify = require('fastify')();

const authGuard = async (req, reply) => {};

// Fastify route options object
fastify.route({
    method: 'DELETE',
    url: '/admin/delete-user',
    handler: async (request, reply) => {
        return { deleted: true };
    }
});

// Fastify route with preHandler guard
fastify.get('/admin/stats', { preHandler: [authGuard] }, async (request, reply) => {
    return { stats: true };
});

module.exports = fastify;
