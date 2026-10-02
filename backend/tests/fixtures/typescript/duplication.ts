// Demonstrates TypeScript structural duplication

interface CartItem {
    id: string;
    cost: number;
    enabled: boolean;
}

export function calculateCart(items: CartItem[], vat: number, discount: number) {
    let total = 0;
    const records = [];
    for (const item of items) {
        if (item.enabled) {
            let base = item.cost * (1 - discount);
            let tax = base * vat;
            let sum = base + tax;
            total += sum;
            records.push({ id: item.id, sum });
        }
    }
    return { total, records };
}

export function calculateQuote(lines: CartItem[], factor: number, deduction: number) {
    let total = 0;
    const records = [];
    for (const line of lines) {
        if (line.enabled) {
            let base = line.cost * (1 - deduction);
            let tax = base * factor;
            let sum = base + tax;
            total += sum;
            records.push({ id: line.id, sum });
        }
    }
    return { total, records };
}
