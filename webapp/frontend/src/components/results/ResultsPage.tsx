import type { FC } from 'react';
import { Link, useParams } from 'react-router-dom';
import Explanation from './Explanation';
import ResultsTable from './ResultsTable';
import { useTestRun } from '../../hooks/useTestRun';

export type ResultsPageProps = {
    runId?: string;
};

const classifyResult = (resultFlags: Record<string, boolean>, detected: boolean) => {
    const activeFlags = Object.entries(resultFlags || {}).filter(([, value]) => value);
    if (detected) return 'Vulnerability';
    if (activeFlags.length) return 'Flagged';
    return 'Safe';
};

const ResultsPage: FC<ResultsPageProps> = ({ runId }) => {
    const params = useParams();
    const targetRunId = runId || params?.runId || '';
    const { run, loading, error, refetch } = useTestRun(targetRunId);

    return (
        <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-900 text-white">
            <div className="container mx-auto px-6 py-8">
                <div className="flex items-center justify-between mb-6">
                    <div>
                        <h1 className="text-3xl font-bold">Test Run Results</h1>
                        <p className="text-gray-400 text-sm">Session ID: {targetRunId || 'Unknown'}</p>
                    </div>
                    <div className="flex gap-2">
                        <Link to="/console" className="px-4 py-2 rounded bg-gray-800/70 border border-gray-700 hover:bg-gray-700/70 text-sm">
                            Back to console
                        </Link>
                        <Link to="/" className="px-4 py-2 rounded bg-gray-800/70 border border-gray-700 hover:bg-gray-700/70 text-sm">
                            Home
                        </Link>
                    </div>
                </div>

                {loading && <div className="text-center py-12 text-gray-300">Loading run data…</div>}

                {error && <div className="bg-red-900/30 border border-red-700 text-red-100 rounded p-4 mb-4">{error}</div>}

                {run && (
                    <div className="space-y-6">
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                            <div className="bg-gray-800/80 border border-gray-700 rounded-lg p-4">
                                <h2 className="text-lg font-semibold text-gray-100 mb-2">Prompt</h2>
                                <div className="bg-black/40 border border-gray-700 rounded p-3 font-mono text-sm text-gray-100 whitespace-pre-wrap">
                                    {run.results[0]?.payload || 'Unknown payload'}
                                </div>
                            </div>
                            <div className="bg-gray-800/80 border border-gray-700 rounded-lg p-4">
                                <div className="flex items-center justify-between mb-2">
                                    <h2 className="text-lg font-semibold text-gray-100">Model Response</h2>
                                    <button
                                        onClick={refetch}
                                        className="text-xs px-3 py-1 rounded bg-gray-700 hover:bg-gray-600 border border-gray-600"
                                    >
                                        Refresh
                                    </button>
                                </div>
                                <div className="bg-black/40 border border-gray-700 rounded p-3 font-mono text-sm text-gray-100 whitespace-pre-wrap min-h-[120px]">
                                    {run.results[0]?.response_preview || 'No response captured'}
                                </div>
                            </div>
                        </div>

                        {run.results.map((result, index) => {
                            const status = classifyResult(result.flags, result.detected);
                            const statusStyles = {
                                Vulnerability: 'bg-red-900/40 border-red-600/60 text-red-200',
                                Flagged: 'bg-yellow-900/40 border-yellow-600/60 text-yellow-100',
                                Safe: 'bg-green-900/30 border-green-600/50 text-green-100',
                            } as const;
                            const activeFlags = Object.entries(result.flags || {}).filter(([, value]) => value);

                            return (
                                <div key={`${result.payload}-${index}`} className={`p-5 rounded-xl border ${statusStyles[status]} shadow-lg`}>
                                    <div className="flex items-center justify-between mb-3">
                                        <div className="flex items-center gap-2">
                                            <span className="px-2 py-1 bg-gray-800/60 rounded text-xs uppercase tracking-wide text-gray-200">{result.category}</span>
                                            <span className="px-2 py-1 rounded text-xs font-semibold border border-white/10">{status}</span>
                                        </div>
                                        <span className="text-xs text-gray-200">{result.timestamp || 'Pending'}</span>
                                    </div>
                                    <div>
                                        <p className="text-sm text-gray-200 font-mono whitespace-pre-wrap bg-black/30 border border-gray-700 rounded p-3">{result.payload}</p>
                                        {result.response_preview && (
                                            <div className="mt-3">
                                                <p className="text-xs uppercase text-gray-400 mb-1">Model response</p>
                                                <div className="text-sm text-gray-100 bg-gray-900/60 border border-gray-700 rounded p-3 whitespace-pre-wrap font-mono">
                                                    {result.response_preview}
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                    <Explanation flags={result.flags || {}} detected={result.detected} />
                                    {activeFlags.length > 0 && (
                                        <div className="mt-3 text-xs text-gray-300">Active flags: {activeFlags.map(([flag]) => flag).join(', ')}</div>
                                    )}
                                </div>
                            );
                        })}

                        <ResultsTable results={run.results} />

                        <div className="flex gap-3 pt-4">
                            <a href={`/api/test/${run.session_id}/report?format=json`} className="px-4 py-2 rounded bg-purple-700 hover:bg-purple-600 text-sm">
                                Download JSON
                            </a>
                            <a href={`/api/test/${run.session_id}/report?format=csv`} className="px-4 py-2 rounded bg-green-700 hover:bg-green-600 text-sm">
                                Download CSV
                            </a>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

export default ResultsPage;
