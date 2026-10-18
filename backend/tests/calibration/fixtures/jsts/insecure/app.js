const express = require('express');
const app = express();
app.use(express.json());

app.post('/admin/delete-user', (req, res) => {
    const query = 'DELETE FROM users WHERE id=' + req.body.id;
    res.json({ deleted: true, query });
});

app.get('/admin/export', (req, res) => {
    res.json({ export: 'all_data' });
});

app.post('/payments/refund', (req, res) => {
    res.json({ refunded: true });
});

module.exports = app;
