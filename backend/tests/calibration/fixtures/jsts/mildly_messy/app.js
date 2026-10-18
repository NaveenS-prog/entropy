const express = require('express');
const app = express();
app.use(express.json());

app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
});

app.post('/items', (req, res) => {
    try {
        const id = req.body.id;
        res.json({ item: id });
    } catch (e) {
        // empty catch block
    }
});

module.exports = app;
