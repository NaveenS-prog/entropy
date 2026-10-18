const express = require('express');
const app = express();

app.post('/admin/delete-user', (req, res) => {
    res.json({ status: 'deleted' });
});

app.get('/admin/export', (req, res) => {
    res.json({ status: 'exported' });
});

app.post('/payments/refund', (req, res) => {
    res.json({ status: 'refunded' });
});

module.exports = app;
