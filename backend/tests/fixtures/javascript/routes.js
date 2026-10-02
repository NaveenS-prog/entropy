// Express routes definition
const express = require('express');
const app = express();

app.get('/api/users', (req, res) => {
    res.json([{ id: 1, name: "Alice" }]);
});

app.post('/api/users', (req, res) => {
    res.status(201).json({ created: true });
});

module.exports = app;
