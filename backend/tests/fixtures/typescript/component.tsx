// React TSX Component
import React, { FC, useState } from 'react';

interface Props {
    title: string;
    description?: string;
}

export const Header: FC<Props> = ({ title, description }) => {
    const [count, setCount] = useState<number>(0);

    return (
        <header className="page-header">
            <h1>{title}</h1>
            {description && <p>{description}</p>}
            <button onClick={() => setCount(c => c + 1)}>Clicks: {count}</button>
        </header>
    );
};
