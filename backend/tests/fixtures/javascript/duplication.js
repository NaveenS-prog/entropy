// Demonstrates structural duplication across functions

export function processOrderBatch(items, taxRate, discount) {
    let total = 0;
    const processed = [];
    for (const item of items) {
        if (item.active) {
            let price = item.price * (1 - discount);
            let tax = price * taxRate;
            let finalPrice = price + tax;
            total += finalPrice;
            processed.push({ id: item.id, finalPrice });
        }
    }
    return { total, processed };
}

export function processInvoiceBatch(entries, rate, rebate) {
    let total = 0;
    const processed = [];
    for (const entry of entries) {
        if (entry.active) {
            let price = entry.price * (1 - rebate);
            let tax = price * rate;
            let finalPrice = price + tax;
            total += finalPrice;
            processed.push({ id: entry.id, finalPrice });
        }
    }
    return { total, processed };
}
