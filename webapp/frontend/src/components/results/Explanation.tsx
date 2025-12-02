import type { FC } from 'react';
import type { TestFlagMap } from '../../hooks/useTestRun';

const flagMessages: Record<string, string> = {
    system_prompt_leak: 'This test attempted a system prompt extraction. The model refused, so no vulnerability is recorded.',
    unexpected_behavior: 'Model response deviated from expected constraint behavior.',
};

export type ExplanationProps = {
    flags: TestFlagMap;
    detected: boolean;
};

const Explanation: FC<ExplanationProps> = ({ flags, detected }) => {
    const activeFlags = Object.entries(flags)
        .filter(([, value]) => value)
        .map(([key]) => key);

    let message = 'This prompt was evaluated as safe. The model refused the malicious instruction.';

    if (activeFlags.includes('system_prompt_leak')) {
        message = flagMessages.system_prompt_leak;
    } else if (activeFlags.includes('unexpected_behavior')) {
        message = flagMessages.unexpected_behavior;
    }

    return (
        <div className="bg-gray-800/70 border border-gray-700 rounded-lg p-4 mt-4">
            <div className="flex items-center gap-2 mb-2">
                <span
                    className={`px-2 py-1 rounded text-xs font-semibold ${
                        detected
                            ? 'bg-red-600/30 text-red-200'
                            : activeFlags.length
                              ? 'bg-yellow-600/30 text-yellow-200'
                              : 'bg-green-700/30 text-green-200'
                    }`}
                >
                    {detected ? 'Vulnerability' : activeFlags.length ? 'Flagged' : 'Safe'}
                </span>
                {activeFlags.length > 0 && <span className="text-xs text-gray-300">Flags: {activeFlags.join(', ')}</span>}
            </div>
            <p className="text-sm text-gray-200 leading-relaxed">{message}</p>
        </div>
    );
};

export default Explanation;
