const express = require('express');
const app = express();
const db = require('./db');

app.post('/api/delete', (req, res) => {
    // Unvalidated req.body.id reaching db.run
    db.run('DELETE FROM users WHERE id=' + req.body.id);
    res.json({ success: true });
});

app.post('/api/safe-delete', (req, res) => {
    // Parameterized query -> should NOT be flagged
    db.run('DELETE FROM users WHERE id = ?', [req.body.id]);
    res.json({ success: true });
});

module.exports = app;
