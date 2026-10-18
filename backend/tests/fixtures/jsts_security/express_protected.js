const express = require('express');
const app = express();

const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) return res.status(401).send();
    next();
};
const requireAdmin = (req, res, next) => {
    if (!req.user || req.user.role !== 'admin') return res.status(403).send();
    next();
};

// Public route
app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
});

// Public login route
app.post('/login', (req, res) => {
    res.json({ token: 'jwt' });
});

// Protected sensitive route with auth & role middleware
app.post('/admin/delete-user', authMiddleware, requireAdmin, (req, res) => {
    res.json({ status: 'deleted' });
});

// Protected route with array middleware
app.post('/payments/refund', [authMiddleware, requireAdmin], (req, res) => {
    res.json({ status: 'refunded' });
});

// Protected route with inline user verification
app.get('/user/profile', (req, res) => {
    const user = req.user;
    res.json({ user });
});

module.exports = app;
