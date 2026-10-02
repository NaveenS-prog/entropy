// Clean TypeScript fixture with full type annotations

interface SummaryStats {
    total: number;
    count: number;
    average: number;
}

export class MetricsCollector {
    private readonly entries: number[] = [];

    public record(val: number): void {
        this.entries.push(val);
    }

    public compute(): SummaryStats {
        if (this.entries.length === 0) {
            return { total: 0, count: 0, average: 0 };
        }
        const total = this.entries.reduce((a, b) => a + b, 0);
        return {
            total,
            count: this.entries.length,
            average: total / this.entries.length,
        };
    }
}
