import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import type { TestResult, TestRun } from '../hooks/useTestRun';

export type ConsoleProps = {
    onBack?: () => void;
};

type EndpointOption = {
    name: string;
    description?: string;
    target_service?: string;
    model?: string;
    endpoint_url?: string;
    has_api_key?: boolean;
};

type PayloadPreset = {
    name: string;
    description?: string;
    test_categories?: string[];
    custom_payloads?: string[];
};

type TestConfig = {
    target_service: string;
    api_key: string;
    model: string;
    endpoint_url: string;
    endpoint_name: string;
    payload_preset: string;
    test_categories: string[];
    custom_payloads: string[];
    max_requests: number | '';
    delay_between_requests: number | '';
};

const defaultTestConfig: TestConfig = {
    target_service: 'anthropic',
    api_key: '',
    model: '',
    endpoint_url: '',
    endpoint_name: '',
    payload_preset: '',
    test_categories: ['baseline'],
    custom_payloads: [],
    max_requests: 50,
    delay_between_requests: 0.5,
};

const Console: React.FC<ConsoleProps> = ({ onBack }) => {
    const [testConfig, setTestConfig] = useState<TestConfig>(defaultTestConfig);
    const [session, setSession] = useState<TestRun | null>(null);
    const [isRunning, setIsRunning] = useState(false);
    const [isShuttingDown, setIsShuttingDown] = useState(false);
    const [results, setResults] = useState<TestResult[]>([]);
    const [ws, setWs] = useState<WebSocket | null>(null);
    const [customPayload, setCustomPayload] = useState('');
    const [endpointOptions, setEndpointOptions] = useState<EndpointOption[]>([]);
    const [payloadPresets, setPayloadPresets] = useState<PayloadPreset[]>([]);
    const [optionsError, setOptionsError] = useState('');
    const navigate = useNavigate();

    useEffect(() => {
        const fetchOptions = async () => {
            try {
                const response = await fetch('/api/config/options');
                if (!response.ok) {
                    throw new Error('Failed to load saved configuration');
                }

                const data = await response.json();
                setEndpointOptions(data.endpoints || []);
                setPayloadPresets(data.payload_presets || []);
            } catch (error) {
                console.error('Config options error:', error);
                setOptionsError('Could not load saved endpoints or payload presets');
            }
        };

        fetchOptions();
    }, []);

    useEffect(() => {
        return () => {
            ws?.close();
        };
    }, [ws]);

    const applyEndpointSelection = (name: string) => {
        const selected = endpointOptions.find((option) => option.name === name);

        setTestConfig((prev) => ({
            ...prev,
            endpoint_name: name,
            target_service: selected?.target_service || prev.target_service,
            model: selected?.model || '',
            endpoint_url: selected?.endpoint_url || '',
            api_key: name ? '' : prev.api_key,
        }));
    };

    const applyPayloadPreset = (name: string) => {
        const preset = payloadPresets.find((item) => item.name === name);

        setTestConfig((prev) => ({
            ...prev,
            payload_preset: name,
            test_categories: preset?.test_categories?.length ? preset.test_categories : ['baseline'],
            custom_payloads: preset?.custom_payloads || [],
        }));
    };

    const selectedEndpoint = useMemo(
        () => endpointOptions.find((option) => option.name === testConfig.endpoint_name),
        [endpointOptions, testConfig.endpoint_name]
    );
    const selectedPreset = useMemo(
        () => payloadPresets.find((option) => option.name === testConfig.payload_preset),
        [payloadPresets, testConfig.payload_preset]
    );
    const shouldShowEndpointUrl = (selectedEndpoint?.target_service || testConfig.target_service) === 'azure_openai';
    const disableControls = isRunning || isShuttingDown;

    const getPreparedTestConfig = (): TestConfig & { max_requests: number; delay_between_requests: number } => {
        const maxRequestsValue = Number(testConfig.max_requests);
        const delayValue = Number(testConfig.delay_between_requests);

        if (!Number.isInteger(maxRequestsValue) || maxRequestsValue <= 0) {
            throw new Error('Please enter a valid positive integer for Max Requests.');
        }

        if (!Number.isFinite(delayValue) || delayValue < 0) {
            throw new Error('Please enter a valid non-negative number for Delay.');
        }

        return {
            ...testConfig,
            max_requests: maxRequestsValue,
            delay_between_requests: delayValue,
        };
    };

    const startTest = async () => {
        const selected = endpointOptions.find((option) => option.name === testConfig.endpoint_name);
        const hasStoredKey = selected?.has_api_key;

        if (!testConfig.api_key && !hasStoredKey) {
            alert('Please enter an API key or select a configured endpoint with credentials');
            return;
        }

        let preparedConfig: ReturnType<typeof getPreparedTestConfig>;

        try {
            preparedConfig = getPreparedTestConfig();
        } catch (error) {
            alert(error instanceof Error ? error.message : 'Invalid configuration');
            return;
        }

        setIsRunning(true);
        setResults([]);

        try {
            const response = await fetch('/api/test/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(preparedConfig),
            });

            if (!response.ok) {
                const errorDetails = await response.json().catch(() => ({}));
                const detailMessage = errorDetails?.detail ? JSON.stringify(errorDetails.detail) : response.statusText;
                throw new Error(detailMessage || 'Request was rejected by the server');
            }

            const data: TestRun = await response.json();
            setSession(data);

            const websocketProtocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
            const websocket = new WebSocket(`${websocketProtocol}://${window.location.host}/ws/${data.session_id}`);

            websocket.onmessage = (event) => {
                const update = JSON.parse(event.data) as TestRun;
                setSession(update);
                setResults(update.results || []);

                if (update.status === 'completed' || update.status === 'failed') {
                    setIsRunning(false);
                    websocket.close();
                }
            };

            websocket.onerror = (error) => {
                console.error('WebSocket error:', error);
                setIsRunning(false);
            };

            setWs(websocket);
        } catch (error) {
            console.error('Failed to start test:', error);
            alert('Failed to start test: ' + (error instanceof Error ? error.message : 'Unknown error'));
            setIsRunning(false);
        }
    };

    const stopTest = () => {
        if (ws) {
            ws.close();
            setWs(null);
        }
        setIsRunning(false);
    };

    const closeApp = async () => {
        if (isShuttingDown) {
            return;
        }

        setIsShuttingDown(true);

        try {
            if (ws) {
                ws.close();
                setWs(null);
            }
            setIsRunning(false);

            const response = await fetch('/api/app/close', {
                method: 'POST',
            });

            if (!response.ok) {
                throw new Error('Failed to request shutdown');
            }

            alert('Shutting down Injecticide. This window may close once the server stops.');
        } catch (error) {
            console.error('Failed to close app:', error);
            alert('Could not close the app: ' + (error instanceof Error ? error.message : 'Unknown error'));
            setIsShuttingDown(false);
        }
    };

    const downloadReport = (format: string) => {
        if (!session) return;
        window.open(`/api/test/${session.session_id}/report?format=${format}`, '_blank');
    };

    const goToResultsPage = () => {
        if (session?.session_id) {
            navigate(`/results/${session.session_id}`);
        }
    };

    const addCustomPayload = () => {
        if (customPayload.trim()) {
            setTestConfig((prev) => ({
                ...prev,
                payload_preset: '',
                custom_payloads: [...prev.custom_payloads, customPayload],
            }));
            setCustomPayload('');
        }
    };

    const removeCustomPayload = (index: number) => {
        setTestConfig((prev) => ({
            ...prev,
            payload_preset: '',
            custom_payloads: prev.custom_payloads.filter((_, i) => i !== index),
        }));
    };

    const handleMaxRequestsChange = (event: React.ChangeEvent<HTMLInputElement>) => {
        const value = event.target.value;

        if (value === '') {
            setTestConfig((prev) => ({ ...prev, max_requests: '' }));
            return;
        }

        const parsed = Number(value);

        if (!Number.isNaN(parsed)) {
            setTestConfig((prev) => ({ ...prev, max_requests: parsed }));
        }
    };

    const handleDelayChange = (event: React.ChangeEvent<HTMLInputElement>) => {
        const value = event.target.value;

        if (value === '') {
            setTestConfig((prev) => ({ ...prev, delay_between_requests: '' }));
            return;
        }

        const parsed = Number(value);

        if (!Number.isNaN(parsed)) {
            setTestConfig((prev) => ({ ...prev, delay_between_requests: parsed }));
        }
    };

    return (
        <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-900">
            <div className="fixed inset-0 overflow-hidden pointer-events-none">
                <div className="absolute -top-40 -right-40 w-80 h-80 bg-red-600 rounded-full filter blur-3xl opacity-20 animate-pulse"></div>
                <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-purple-600 rounded-full filter blur-3xl opacity-20 animate-pulse"></div>
            </div>

            <header className="relative bg-gradient-to-r from-black/70 via-gray-900/70 to-black/70 backdrop-blur-sm shadow-2xl border-b border-red-600/50">
                <div className="container mx-auto px-6 py-4">
                    <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                        <div className="flex items-center space-x-4">
                            <div className="h-12 w-12 rounded-lg shadow-lg bg-gradient-to-br from-red-700 via-red-600 to-red-800 border border-red-500/70 flex items-center justify-center text-white font-extrabold text-xl">
                                IF
                            </div>
                            <div>
                                <h1 className="text-3xl md:text-4xl font-bold flex items-center space-x-2">
                                    <span className="text-white drop-shadow">Injecticide</span>
                                    <span className="text-xs font-semibold uppercase tracking-widest text-gray-400 bg-red-900/40 border border-red-700/40 px-2 py-1 rounded-md">DAF-TECH</span>
                                </h1>
                                <p className="text-sm text-gray-300">Enterprise LLM Security Testing Platform</p>
                            </div>
                        </div>
                        <div className="flex items-center space-x-3">
                            {onBack && (
                                <button
                                    onClick={onBack}
                                    className="px-4 py-2 rounded-lg text-sm font-semibold transition border border-gray-600/70 bg-gray-800/70 hover:bg-gray-700/80 text-gray-200"
                                >
                                    <i className="fas fa-arrow-left mr-2"></i>
                                    Back to Overview
                                </button>
                            )}
                            <span className="hidden sm:inline-flex items-center text-gray-300 text-sm bg-gray-800/60 border border-gray-700/60 px-3 py-2 rounded-lg shadow-lg">
                                <i className="fas fa-shield-alt text-red-400 mr-2"></i>
                                Enterprise Grade Security Testing
                            </span>
                            <button
                                onClick={closeApp}
                                disabled={isShuttingDown}
                                className={`px-4 py-2 rounded-lg text-sm font-semibold transition border border-red-600/70 bg-red-800/80 hover:bg-red-700/80 ${
                                    isShuttingDown ? 'opacity-60 cursor-not-allowed' : ''
                                }`}
                            >
                                <i className="fas fa-power-off mr-2"></i>
                                {isShuttingDown ? 'Closing…' : 'Close App'}
                            </button>
                        </div>
                    </div>
                </div>
            </header>

            <div className="relative container mx-auto px-6 py-8">
                <div className="grid grid-cols-1 xl:grid-cols-3 gap-8">
                    <div className="xl:col-span-1">
                        <div className="bg-gray-800/90 backdrop-blur rounded-xl p-6 shadow-2xl border border-gray-700/50">
                            <h2 className="text-xl font-bold mb-6 text-red-400 flex items-center">
                                <i className="fas fa-cog mr-2"></i>Test Configuration
                            </h2>

                            <div className="space-y-4">
                                <div>
                                    <label className="block text-sm font-medium mb-2 text-gray-300">
                                        <i className="fas fa-bookmark mr-1 text-blue-400"></i>Saved Endpoint
                                    </label>
                                    <select
                                        className="w-full bg-gray-900/50 border border-gray-600 rounded-lg px-4 py-2 text-white focus:border-red-500 focus:outline-none transition"
                                        value={testConfig.endpoint_name}
                                        onChange={(e) => applyEndpointSelection(e.target.value)}
                                        disabled={disableControls}
                                    >
                                        <option value="">Manual configuration</option>
                                        {endpointOptions.map((option) => (
                                            <option key={option.name} value={option.name}>
                                                {option.name} {option.description ? `- ${option.description}` : ''}
                                            </option>
                                        ))}
                                    </select>
                                    {optionsError && <p className="text-xs text-yellow-400 mt-1">{optionsError}</p>}
                                    {selectedEndpoint && <p className="text-xs text-gray-400 mt-1">{selectedEndpoint.description || 'Using server-stored credentials.'}</p>}
                                </div>

                                <div>
                                    <label className="block text-sm font-medium mb-2 text-gray-300">
                                        <i className="fas fa-bullseye mr-1 text-red-400"></i>Target Service
                                    </label>
                                    <select
                                        className="w-full bg-gray-900/50 border border-gray-600 rounded-lg px-4 py-2 text-white focus:border-red-500 focus:outline-none transition"
                                        value={testConfig.target_service}
                                        onChange={(e) => setTestConfig({ ...testConfig, target_service: e.target.value })}
                                        disabled={disableControls}
                                    >
                                        <option value="anthropic">🤖 Anthropic (Claude)</option>
                                        <option value="openai">🧠 OpenAI (GPT)</option>
                                        <option value="azure_openai">☁️ Azure OpenAI</option>
                                    </select>
                                </div>

                                <div>
                                    <label className="block text-sm font-medium mb-2 text-gray-300">
                                        <i className="fas fa-key mr-1 text-yellow-400"></i>API Key
                                    </label>
                                    <input
                                        type="password"
                                        className="w-full bg-gray-900/50 border border-gray-600 rounded-lg px-4 py-2 text-white focus:border-red-500 focus:outline-none transition"
                                        placeholder="sk-..."
                                        value={testConfig.api_key}
                                        onChange={(e) => setTestConfig({ ...testConfig, api_key: e.target.value })}
                                        disabled={disableControls}
                                    />
                                    {selectedEndpoint && <p className="text-xs text-gray-400 mt-1">API key is stored on the server for this preset; override here if needed.</p>}
                                </div>

                                <div>
                                    <label className="block text-sm font-medium mb-2 text-gray-300">
                                        <i className="fas fa-brain mr-1 text-purple-400"></i>Model (optional)
                                    </label>
                                    <input
                                        type="text"
                                        className="w-full bg-gray-900/50 border border-gray-600 rounded-lg px-4 py-2 text-white focus:border-red-500 focus:outline-none transition"
                                        placeholder="Default model"
                                        value={testConfig.model}
                                        onChange={(e) => setTestConfig({ ...testConfig, model: e.target.value })}
                                        disabled={disableControls}
                                    />
                                </div>

                                {shouldShowEndpointUrl && (
                                    <div>
                                        <label className="block text-sm font-medium mb-2 text-gray-300">
                                            <i className="fas fa-link mr-1 text-blue-400"></i>Azure Endpoint URL
                                        </label>
                                        <input
                                            type="text"
                                            className="w-full bg-gray-900/50 border border-gray-600 rounded-lg px-4 py-2 text-white focus:border-red-500 focus:outline-none transition"
                                            placeholder="https://your-resource.openai.azure.com"
                                            value={testConfig.endpoint_url}
                                            onChange={(e) => setTestConfig({ ...testConfig, endpoint_url: e.target.value })}
                                            disabled={disableControls}
                                        />
                                    </div>
                                )}

                                <div>
                                    <label className="block text-sm font-medium mb-2 text-gray-300">
                                        <i className="fas fa-vial mr-1 text-green-400"></i>Test Categories
                                    </label>
                                    <div className="flex gap-2 mb-2">
                                        <select
                                            className="flex-1 bg-gray-900/50 border border-gray-600 rounded-lg px-3 py-2 text-white focus:border-red-500 focus:outline-none text-sm"
                                            value={testConfig.payload_preset}
                                            onChange={(e) => applyPayloadPreset(e.target.value)}
                                            disabled={disableControls}
                                        >
                                            <option value="">Custom selection</option>
                                            {payloadPresets.map((preset) => (
                                                <option key={preset.name} value={preset.name}>
                                                    {preset.name}
                                                </option>
                                            ))}
                                        </select>
                                        {selectedPreset && <span className="text-xs text-gray-400 self-center">{selectedPreset.description || 'Preset loaded from secure config'}</span>}
                                    </div>
                                    <div className="space-y-2">
                                        <label className="flex items-center p-2 bg-gray-900/30 rounded hover:bg-gray-900/50 transition cursor-pointer">
                                            <input
                                                type="checkbox"
                                                className="mr-3 w-4 h-4 text-red-600 rounded focus:ring-red-500"
                                                checked={testConfig.test_categories.includes('baseline')}
                                                onChange={(e) => {
                                                    if (e.target.checked) {
                                                        setTestConfig({ ...testConfig, payload_preset: '', test_categories: [...testConfig.test_categories, 'baseline'] });
                                                    } else {
                                                        setTestConfig({
                                                            ...testConfig,
                                                            payload_preset: '',
                                                            test_categories: testConfig.test_categories.filter((c) => c !== 'baseline'),
                                                        });
                                                    }
                                                }}
                                                disabled={disableControls}
                                            />
                                            <div>
                                                <div className="font-medium">Baseline Injections</div>
                                                <div className="text-xs text-gray-400">Standard prompt injection tests</div>
                                            </div>
                                        </label>
                                        <label className="flex items-center p-2 bg-gray-900/30 rounded hover:bg-gray-900/50 transition cursor-pointer">
                                            <input
                                                type="checkbox"
                                                className="mr-3 w-4 h-4 text-red-600 rounded focus:ring-red-500"
                                                checked={testConfig.test_categories.includes('policy')}
                                                onChange={(e) => {
                                                    if (e.target.checked) {
                                                        setTestConfig({ ...testConfig, payload_preset: '', test_categories: [...testConfig.test_categories, 'policy'] });
                                                    } else {
                                                        setTestConfig({
                                                            ...testConfig,
                                                            payload_preset: '',
                                                            test_categories: testConfig.test_categories.filter((c) => c !== 'policy'),
                                                        });
                                                    }
                                                }}
                                                disabled={disableControls}
                                            />
                                            <div>
                                                <div className="font-medium">Policy Violations</div>
                                                <div className="text-xs text-gray-400">Safety guardrail tests</div>
                                            </div>
                                        </label>
                                    </div>
                                </div>

                                <div>
                                    <label className="block text-sm font-medium mb-2 text-gray-300">
                                        <i className="fas fa-code mr-1 text-blue-400"></i>Custom Payloads
                                    </label>
                                    <div className="flex gap-2">
                                        <input
                                            type="text"
                                            className="flex-1 bg-gray-900/50 border border-gray-600 rounded-lg px-4 py-2 text-white focus:border-red-500 focus:outline-none transition"
                                            placeholder="Add custom payload..."
                                            value={customPayload}
                                            onChange={(e) => setCustomPayload(e.target.value)}
                                            onKeyDown={(e) => e.key === 'Enter' && addCustomPayload()}
                                            disabled={disableControls}
                                        />
                                        <button
                                            onClick={addCustomPayload}
                                            disabled={disableControls}
                                            className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg transition disabled:opacity-50"
                                        >
                                            <i className="fas fa-plus"></i>
                                        </button>
                                    </div>
                                    {testConfig.custom_payloads.length > 0 && (
                                        <div className="mt-2 space-y-1">
                                            {testConfig.custom_payloads.map((payload, idx) => (
                                                <div key={idx} className="flex items-center justify-between p-2 bg-gray-900/30 rounded-lg border border-gray-800">
                                                    <span className="text-sm text-gray-200">{payload}</span>
                                                    <button
                                                        onClick={() => removeCustomPayload(idx)}
                                                        className="text-red-400 hover:text-red-300 text-xs"
                                                        disabled={disableControls}
                                                    >
                                                        Remove
                                                    </button>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>

                                <div className="grid grid-cols-2 gap-4">
                                    <div>
                                        <label className="block text-sm font-medium mb-2 text-gray-300">
                                            <i className="fas fa-hashtag mr-1 text-indigo-400"></i>Max Requests
                                        </label>
                                        <input
                                            type="number"
                                            min={1}
                                            className="w-full bg-gray-900/50 border border-gray-600 rounded-lg px-4 py-2 text-white focus:border-red-500 focus:outline-none transition"
                                            value={testConfig.max_requests}
                                            onChange={handleMaxRequestsChange}
                                            disabled={disableControls}
                                        />
                                    </div>
                                    <div>
                                        <label className="block text-sm font-medium mb-2 text-gray-300">
                                            <i className="fas fa-clock mr-1 text-green-400"></i>Delay (seconds)
                                        </label>
                                        <input
                                            type="number"
                                            min={0}
                                            step="0.1"
                                            className="w-full bg-gray-900/50 border border-gray-600 rounded-lg px-4 py-2 text-white focus:border-red-500 focus:outline-none transition"
                                            value={testConfig.delay_between_requests}
                                            onChange={handleDelayChange}
                                            disabled={disableControls}
                                        />
                                    </div>
                                </div>

                                <div className="flex gap-3 pt-2">
                                    <button
                                        onClick={startTest}
                                        disabled={isRunning || isShuttingDown}
                                        className="flex-1 bg-red-600 hover:bg-red-700 text-white font-semibold px-4 py-3 rounded-lg shadow-lg border border-red-500/60 disabled:opacity-60"
                                    >
                                        <i className="fas fa-play mr-2"></i>Launch Attack
                                    </button>
                                    <button
                                        onClick={stopTest}
                                        disabled={!isRunning}
                                        className="px-4 py-3 rounded-lg border border-gray-600 bg-gray-800 text-gray-200 hover:bg-gray-700 disabled:opacity-50"
                                    >
                                        <i className="fas fa-stop mr-2"></i>Stop
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div className="xl:col-span-2">
                        <div className="bg-gray-900/80 rounded-2xl border border-gray-800 shadow-2xl p-6">
                            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-4">
                                <div>
                                    <h2 className="text-xl font-bold text-white flex items-center gap-2">
                                        <i className="fas fa-shield-virus text-red-400"></i>
                                        Live Test Run
                                    </h2>
                                    <p className="text-sm text-gray-400">Monitor prompt injection probes in real-time</p>
                                </div>
                                <div className="flex gap-2">
                                    <button
                                        onClick={() => downloadReport('json')}
                                        disabled={!session}
                                        className="px-3 py-2 rounded bg-purple-700/80 text-sm border border-purple-600/70 hover:bg-purple-600/80 disabled:opacity-50"
                                    >
                                        <i className="fas fa-download mr-1"></i>JSON Report
                                    </button>
                                    <button
                                        onClick={() => downloadReport('csv')}
                                        disabled={!session}
                                        className="px-3 py-2 rounded bg-green-700/80 text-sm border border-green-600/70 hover:bg-green-600/80 disabled:opacity-50"
                                    >
                                        <i className="fas fa-file-csv mr-1"></i>CSV Report
                                    </button>
                                    <button
                                        onClick={goToResultsPage}
                                        disabled={!session}
                                        className="px-3 py-2 rounded bg-blue-700/80 text-sm border border-blue-600/70 hover:bg-blue-600/80 disabled:opacity-50"
                                    >
                                        <i className="fas fa-chart-line mr-1"></i>View Results
                                    </button>
                                </div>
                            </div>

                            {session && (
                                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                                    <div className="p-4 rounded-lg bg-gray-800/70 border border-gray-700">
                                        <div className="text-sm text-gray-400">Status</div>
                                        <div className="text-xl font-semibold text-white capitalize">{session.status}</div>
                                    </div>
                                    <div className="p-4 rounded-lg bg-gray-800/70 border border-gray-700">
                                        <div className="text-sm text-gray-400">Progress</div>
                                        <div className="text-xl font-semibold text-white">{session.progress}/{session.total_tests}</div>
                                    </div>
                                    <div className="p-4 rounded-lg bg-gray-800/70 border border-gray-700">
                                        <div className="text-sm text-gray-400">Max Requests</div>
                                        <div className="text-xl font-semibold text-white">{session.max_requests ?? testConfig.max_requests}</div>
                                    </div>
                                </div>
                            )}

                            {results.length > 0 ? (
                                <div className="space-y-4">
                                    {results.map((result, idx) => (
                                        <div
                                            key={`${result.payload}-${idx}`}
                                            className={`p-4 rounded-lg border transition-all hover:shadow-lg ${
                                                result.detected
                                                    ? 'bg-red-900/20 border-red-600/50 hover:border-red-500'
                                                    : 'bg-gray-800/50 border-gray-700/50 hover:border-gray-600'
                                            }`}
                                        >
                                            <div className="flex items-start justify-between">
                                                <div className="flex-1">
                                                    <div className="flex items-center gap-2 mb-2">
                                                        <span
                                                            className={`px-2 py-1 rounded text-xs font-medium ${
                                                                result.category === 'baseline'
                                                                    ? 'bg-blue-600/30 text-blue-300'
                                                                    : result.category === 'policy'
                                                                      ? 'bg-purple-600/30 text-purple-300'
                                                                      : 'bg-gray-600/30 text-gray-300'
                                                            }`}
                                                        >
                                                            {result.category}
                                                        </span>
                                                        {result.detected && (
                                                            <span className="px-2 py-1 bg-red-600/30 text-red-300 rounded text-xs font-medium animate-pulse">
                                                                <i className="fas fa-exclamation-triangle mr-1"></i>DETECTED
                                                            </span>
                                                        )}
                                                    </div>
                                                    <div className="text-sm font-mono text-gray-300 mb-1">
                                                        {result.payload.substring(0, 150)}
                                                        {result.payload.length > 150 && '...'}
                                                    </div>
                                                    {result.detected && (
                                                        <div className="text-xs text-red-400 mt-1">
                                                            <i className="fas fa-flag mr-1"></i>
                                                            Triggered: {Object.keys(result.flags).filter((k) => result.flags[k]).join(', ')}
                                                        </div>
                                                    )}
                                                    {result.error && (
                                                        <div className="text-xs text-yellow-400 mt-1">
                                                            <i className="fas fa-exclamation-circle mr-1"></i>
                                                            Error: {result.error}
                                                        </div>
                                                    )}
                                                </div>
                                                <div className="ml-4">
                                                    {result.detected ? (
                                                        <div className="text-red-500 text-2xl">
                                                            <i className="fas fa-shield-virus"></i>
                                                        </div>
                                                    ) : result.error ? (
                                                        <div className="text-yellow-500 text-2xl">
                                                            <i className="fas fa-exclamation-triangle"></i>
                                                        </div>
                                                    ) : (
                                                        <div className="text-green-500 text-2xl">
                                                            <i className="fas fa-shield-alt"></i>
                                                        </div>
                                                    )}
                                                </div>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            ) : (
                                <div className="text-center py-16">
                                    {isRunning ? (
                                        <div>
                                            <div className="text-6xl text-red-500 mb-4 animate-spin">
                                                <i className="fas fa-spinner"></i>
                                            </div>
                                            <p className="text-xl text-gray-300">Executing security tests...</p>
                                            <p className="text-sm text-gray-500 mt-2">Please wait while we probe the target</p>
                                        </div>
                                    ) : (
                                        <div>
                                            <div className="text-6xl text-gray-600 mb-4">
                                                <i className="fas fa-flask"></i>
                                            </div>
                                            <p className="text-xl text-gray-400">No test results yet</p>
                                            <p className="text-sm text-gray-500 mt-2">Configure your test and click "Launch Attack" to begin</p>
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Console;
