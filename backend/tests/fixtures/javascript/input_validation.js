// Demonstrates unvalidated input reaching sensitive sinks in JavaScript

const express = require('express');
const { exec } = require('child_process');
const db = require('./db');

const router = express.Router();

router.post('/search', (req, res) => {
    // Unvalidated req.query passed directly to db query
    db.query(`SELECT * FROM products WHERE name = '${req.query.q}'`);
    res.json({ status: "searched" });
});

router.post('/run-command', (req, res) => {
    // Unvalidated req.body passed to shell execution sink
    exec(`python script.py ${req.body.argument}`);
    res.json({ status: "executed" });
});

module.exports = router;
