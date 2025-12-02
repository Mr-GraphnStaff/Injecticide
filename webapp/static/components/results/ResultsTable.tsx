type TestResult = {
    payload: string;
    category: string;
    flags: Record<string, boolean>;
    detected: boolean;
    timestamp?: string;
};

type ResultsTableProps = {
    results: TestResult[];
};

const ResultsTable = ({ results }: ResultsTableProps) => (
    <div className="overflow-x-auto mt-6">
        <table className="min-w-full divide-y divide-gray-700">
            <thead className="bg-gray-800/70">
                <tr>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-gray-300 uppercase tracking-wider">Category</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-gray-300 uppercase tracking-wider">Flags</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-gray-300 uppercase tracking-wider">Detected</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-gray-300 uppercase tracking-wider">Timestamp</th>
                </tr>
            </thead>
            <tbody className="bg-gray-900/60 divide-y divide-gray-800">
                {results.map((result, index) => {
                    const activeFlags = Object.entries(result.flags || {}).filter(([, value]) => value).map(([flag]) => flag);
                    return (
                        <tr key={`${result.category}-${index}`}>
                            <td className="px-4 py-3 text-sm text-gray-100 font-medium">{result.category}</td>
                            <td className="px-4 py-3 text-sm text-gray-300">{activeFlags.length ? activeFlags.join(', ') : 'None'}</td>
                            <td className="px-4 py-3 text-sm">
                                <span className={`px-2 py-1 rounded text-xs font-semibold ${result.detected ? 'bg-red-600/30 text-red-200' : activeFlags.length ? 'bg-yellow-600/30 text-yellow-200' : 'bg-green-700/30 text-green-200'}`}>
                                    {result.detected ? 'Vulnerability' : activeFlags.length ? 'Flagged' : 'Safe'}
                                </span>
                            </td>
                            <td className="px-4 py-3 text-sm text-gray-300">{result.timestamp || 'Pending'}</td>
                        </tr>
                    );
                })}
            </tbody>
        </table>
    </div>
);

// @ts-ignore expose globally for reuse
window.ResultsTable = ResultsTable;
