const { useEffect, useState } = React;

type TestFlagMap = Record<string, boolean>;

type TestResult = {
    payload: string;
    category: string;
    flags: TestFlagMap;
    response_preview?: string;
    detected: boolean;
    timestamp?: string;
    error?: string;
};

type TestRunSummary = {
    total_tests?: number;
    vulnerabilities_detected?: number;
    detection_rate?: string;
    categories_tested?: string[];
    error?: string;
};

type TestRun = {
    session_id: string;
    status: string;
    progress: number;
    total_tests: number;
    results: TestResult[];
    summary?: TestRunSummary;
    endpoint_name?: string | null;
    payload_preset?: string | null;
    max_requests?: number;
};

type UseTestRunState = {
    run: TestRun | null;
    loading: boolean;
    error: string;
    refetch: () => Promise<void>;
};

const defaultState: Pick<UseTestRunState, 'loading' | 'error'> = {
    loading: true,
    error: '',
};

async function fetchRun(runId: string, setRun: (value: TestRun | null) => void, setError: (value: string) => void, setLoading: (value: boolean) => void) {
    try {
        setLoading(true);
        const response = await fetch(`/api/test/${runId}`);
        if (!response.ok) {
            throw new Error('Unable to load test run');
        }
        const data = await response.json();
        setRun(data as TestRun);
        setError('');
    } catch (err) {
        console.error('Failed to fetch test run', err);
        setError(err instanceof Error ? err.message : 'Unknown error while loading test run');
    } finally {
        setLoading(false);
    }
}

function useTestRun(runId: string): UseTestRunState {
    const [run, setRun] = useState<TestRun | null>(null);
    const [loading, setLoading] = useState(defaultState.loading);
    const [error, setError] = useState(defaultState.error);

    useEffect(() => {
        if (runId) {
            fetchRun(runId, setRun, setError, setLoading);
        }
    }, [runId]);

    const refetch = async () => {
        if (runId) {
            await fetchRun(runId, setRun, setError, setLoading);
        }
    };

    return { run, loading, error, refetch };
}

// @ts-ignore make available globally for inline modules
window.useTestRun = useTestRun;
window.TestRunTypes = { useTestRun };
