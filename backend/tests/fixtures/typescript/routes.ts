// Fastify routes definition in TypeScript
import Fastify, { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

const server: FastifyInstance = Fastify();

server.get('/health', async (request: FastifyRequest, reply: FastifyReply) => {
    return { status: "ok" };
});

server.post('/data', async (request: FastifyRequest, reply: FastifyReply) => {
    reply.status(201).send({ stored: true });
});

export default server;
