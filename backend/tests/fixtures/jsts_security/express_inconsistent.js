const express = require('express');
const app = express();

const authMiddleware = (req, res, next) => next();
const requireAdmin = (req, res, next) => next();

// In the /admin route group:
// /admin/dashboard enforces auth and authorization
app.get('/admin/dashboard', authMiddleware, requireAdmin, (req, res) => {
    res.json({ dashboard: true });
});

// /admin/delete-user omits authentication and authorization
app.post('/admin/delete-user', (req, res) => {
    res.json({ deleted: true });
});

module.exports = app;
