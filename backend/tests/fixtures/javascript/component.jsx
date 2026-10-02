// React JSX Component
import React, { useState } from 'react';

export function UserCard({ user }) {
    const [expanded, setExpanded] = useState(false);

    return (
        <div className="card">
            <h3>{user.name}</h3>
            {expanded && <p>{user.bio}</p>}
            <button onClick={() => setExpanded(!expanded)}>
                {expanded ? "Collapse" : "Expand"}
            </button>
        </div>
    );
}
