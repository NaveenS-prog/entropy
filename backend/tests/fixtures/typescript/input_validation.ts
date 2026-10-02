// Unvalidated input reaching database query in TypeScript
import { Request, Response } from 'express';
import { db } from './database';

export async function handleUserSearch(req: Request, res: Response): Promise<void> {
    const query = req.query.searchTerm as string;
    // Unvalidated req.query passed directly to query sink
    const results = await db.query(`SELECT * FROM users WHERE name LIKE '%${req.query.searchTerm}%'`);
    res.json(results);
}
