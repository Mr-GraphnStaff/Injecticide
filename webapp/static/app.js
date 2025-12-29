const { useState, useEffect, useRef } = React;

function App({ onBack }) {
    const [testConfig, setTestConfig] = useState({
        target_service: 'anthropic',
        api_key: '',
        model: '',
        endpoint_url: '',
        endpoint_name: '',
        payload_preset: '',
        test_categories: ['baseline'],
        custom_payloads: [],
        max_requests: 50,
        delay_between_requests: 0.5
    });

    const [session, setSession] = useState(null);
    const [isRunning, setIsRunning] = useState(false);
    const [isShuttingDown, setIsShuttingDown] = useState(false);
    const [results, setResults] = useState([]);
    const [ws, setWs] = useState(null);
    const [customPayload, setCustomPayload] = useState('');
    const [endpointOptions, setEndpointOptions] = useState([]);
    const [payloadPresets, setPayloadPresets] = useState([]);
    const [payloadCategories, setPayloadCategories] = useState([]);
    const [optionsError, setOptionsError] = useState('');
    const [payloadCategoriesError, setPayloadCategoriesError] = useState('');
    const [skillFile, setSkillFile] = useState(null);
    const [skillScanResult, setSkillScanResult] = useState(null);
    const [skillScanError, setSkillScanError] = useState('');
    const [isScanningSkill, setIsScanningSkill] = useState(false);

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
        const fetchPayloadCategories = async () => {
            try {
                const response = await fetch('/api/payloads');
                if (!response.ok) {
                    throw new Error('Failed to load payload categories');
                }

                const data = await response.json();
                const categories = data.categories || [];
                setPayloadCategories(categories);

                if (categories.length === 0) {
                    return;
                }

                setTestConfig((current) => {
                    const availableIds = new Set(categories.map((category) => category.id));
                    const validSelections = (current.test_categories || []).filter((category) => availableIds.has(category));

                    if (validSelections.length > 0) {
                        return { ...current, test_categories: validSelections };
                    }

                    return { ...current, test_categories: [categories[0].id] };
                });
            } catch (error) {
                console.error('Payload category error:', error);
                setPayloadCategoriesError('Could not load payload categories');
            }
        };

        fetchPayloadCategories();
    }, []);

    const applyEndpointSelection = (name) => {
        const selected = endpointOptions.find((option) => option.name === name);

        setTestConfig((current) => ({
            ...current,
            endpoint_name: name,
            target_service: selected?.target_service || current.target_service,
            model: selected?.model || '',
            endpoint_url: selected?.endpoint_url || '',
            api_key: name ? '' : current.api_key,
        }));
    };

    const filterToAvailableCategories = (categories) => {
        if (!payloadCategories.length) {
            return categories || [];
        }

        const allowedCategories = new Set(payloadCategories.map((category) => category.id));
        const filtered = (categories || []).filter((category) => allowedCategories.has(category));

        if (filtered.length > 0) {
            return filtered;
        }

        return payloadCategories.length ? [payloadCategories[0].id] : [];
    };

    const applyPayloadPreset = (name) => {
        const preset = payloadPresets.find((item) => item.name === name);

        setTestConfig((current) => {
            const presetCategories = preset?.test_categories?.length ? preset.test_categories : ['baseline'];
            const validatedCategories = filterToAvailableCategories(presetCategories);

            return {
                ...current,
                payload_preset: name,
                test_categories: validatedCategories.length ? validatedCategories : current.test_categories,
                custom_payloads: preset?.custom_payloads || [],
            };
        });
    };

    const toggleCategorySelection = (categoryId) => {
        setTestConfig((current) => {
            const hasCategory = current.test_categories.includes(categoryId);
            const updatedCategories = hasCategory
                ? current.test_categories.filter((category) => category !== categoryId)
                : [...current.test_categories, categoryId];

            return { ...current, payload_preset: '', test_categories: updatedCategories };
        });
    };

    const selectedEndpoint = endpointOptions.find((option) => option.name === testConfig.endpoint_name);
    const selectedPreset = payloadPresets.find((option) => option.name === testConfig.payload_preset);
    const shouldShowEndpointUrl = (selectedEndpoint?.target_service || testConfig.target_service) === 'azure_openai';
    const disableControls = isRunning || isShuttingDown;
    
    const getPreparedTestConfig = () => {
        const maxRequestsValue = Number(testConfig.max_requests);
        const delayValue = Number(testConfig.delay_between_requests);

        if (!Number.isInteger(maxRequestsValue) || maxRequestsValue <= 0) {
            throw new Error('Please enter a valid positive integer for Max Requests.');
        }

        if (!Number.isFinite(delayValue) || delayValue < 0) {
            throw new Error('Please enter a valid non-negative number for Delay.');
        }

        const validatedCategories = filterToAvailableCategories(testConfig.test_categories);

        return {
            ...testConfig,
            test_categories: validatedCategories,
            max_requests: maxRequestsValue,
            delay_between_requests: delayValue,
        };
    };

    const startTest = async () => {
        const selectedEndpoint = endpointOptions.find((option) => option.name === testConfig.endpoint_name);
        const hasStoredKey = selectedEndpoint?.has_api_key;

        if (!testConfig.api_key && !hasStoredKey) {
            alert('Please enter an API key or select a configured endpoint with credentials');
            return;
        }

        let preparedConfig;

        try {
            preparedConfig = getPreparedTestConfig();
        } catch (error) {
            alert(error.message);
            return;
        }

        if (!preparedConfig.test_categories || preparedConfig.test_categories.length === 0) {
            alert('Select at least one payload category to run.');
            return;
        }

        setIsRunning(true);
        setResults([]);

        try {
            const response = await fetch('/api/test/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(preparedConfig)
            });

            if (!response.ok) {
                const errorDetails = await response.json().catch(() => ({}));
                const detailMessage = errorDetails?.detail ? JSON.stringify(errorDetails.detail) : response.statusText;
                throw new Error(detailMessage || 'Request was rejected by the server');
            }

            const data = await response.json();
            setSession(data);
            
            // Connect WebSocket for live updates
            const websocketProtocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
            const websocket = new WebSocket(`${websocketProtocol}://${window.location.host}/ws/${data.session_id}`);
            
            websocket.onmessage = (event) => {
                const update = JSON.parse(event.data);
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
            alert('Failed to start test: ' + error.message);
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
            alert('Could not close the app: ' + error.message);
            setIsShuttingDown(false);
        }
    };
    
    const downloadReport = (format) => {
        if (!session) return;
        window.open(`/api/test/${session.session_id}/report?format=${format}`, '_blank');
    };
    
    const addCustomPayload = () => {
        if (customPayload.trim()) {
            setTestConfig({
                ...testConfig,
                payload_preset: '',
                custom_payloads: [...testConfig.custom_payloads, customPayload]
            });
            setCustomPayload('');
        }
    };

    const removeCustomPayload = (index) => {
        setTestConfig({
            ...testConfig,
            payload_preset: '',
            custom_payloads: testConfig.custom_payloads.filter((_, i) => i !== index)
        });
    };

    const handleMaxRequestsChange = (event) => {
        const value = event.target.value;

        if (value === '') {
            setTestConfig({...testConfig, max_requests: ''});
            return;
        }

        const parsed = Number(value);

        if (!Number.isNaN(parsed)) {
            setTestConfig({...testConfig, max_requests: parsed});
        }
    };

    const handleDelayChange = (event) => {
        const value = event.target.value;

        if (value === '') {
            setTestConfig({...testConfig, delay_between_requests: ''});
            return;
        }

        const parsed = Number(value);

        if (!Number.isNaN(parsed)) {
            setTestConfig({...testConfig, delay_between_requests: parsed});
        }
    };

    const resetSkillScanState = () => {
        setSkillScanResult(null);
        setSkillScanError('');
    };

    const handleSkillFileChange = (event) => {
        const file = event.target.files?.[0] || null;
        setSkillFile(file);
        resetSkillScanState();
    };

    const scanSkillFile = async () => {
        if (!skillFile) {
            setSkillScanError('Select a .skill or .zip file to scan.');
            return;
        }

        resetSkillScanState();
        setIsScanningSkill(true);

        try {
            const formData = new FormData();
            formData.append('file', skillFile);

            const response = await fetch('/api/skills/scan', {
                method: 'POST',
                body: formData,
            });

            if (!response.ok) {
                const errorDetails = await response.json().catch(() => ({}));
                const detailMessage = errorDetails?.detail || response.statusText;
                throw new Error(detailMessage || 'Scan failed');
            }

            const data = await response.json();
            setSkillScanResult(data);
        } catch (error) {
            console.error('Skill scan failed:', error);
            setSkillScanError(error.message || 'Scan failed');
        } finally {
            setIsScanningSkill(false);
        }
    };
    
    return (
        <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-900">
            {/* Animated Background */}
            <div className="fixed inset-0 overflow-hidden pointer-events-none">
                <div className="absolute -top-40 -right-40 w-80 h-80 bg-red-600 rounded-full filter blur-3xl opacity-20 animate-pulse"></div>
                <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-purple-600 rounded-full filter blur-3xl opacity-20 animate-pulse"></div>
            </div>
            
            {/* Header */}
            <header className="relative bg-gradient-to-r from-black/70 via-gray-900/70 to-black/70 backdrop-blur-sm shadow-2xl border-b border-red-600/50">
                <div className="container mx-auto px-6 py-4">
                    <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                        <div className="flex items-center space-x-4">
                            <img src="/images/logo.png" alt="DAF-TECH logo" className="h-12 w-12 rounded-lg shadow-lg" />
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
                                className={`px-4 py-2 rounded-lg text-sm font-semibold transition border border-red-600/70 bg-red-800/80 hover:bg-red-700/80 ${isShuttingDown ? 'opacity-60 cursor-not-allowed' : ''}`}
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
                    {/* Configuration Panel */}
                    <div className="xl:col-span-1">
                        <div className="bg-gray-800/90 backdrop-blur rounded-xl p-6 shadow-2xl border border-gray-700/50">
                            <h2 className="text-xl font-bold mb-6 text-red-400 flex items-center">
                                <i className="fas fa-cog mr-2"></i>Test Configuration
                            </h2>
                            
                            <div className="space-y-4">
                                {/* Saved Endpoint */}
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
                                    {optionsError && (
                                        <p className="text-xs text-yellow-400 mt-1">{optionsError}</p>
                                    )}
                                    {selectedEndpoint && (
                                        <p className="text-xs text-gray-400 mt-1">
                                            {selectedEndpoint.description || 'Using server-stored credentials.'}
                                        </p>
                                    )}
                                </div>

                                {/* Target Service */}
                                <div>
                                    <label className="block text-sm font-medium mb-2 text-gray-300">
                                        <i className="fas fa-bullseye mr-1 text-red-400"></i>Target Service
                                    </label>
                                    <select 
                                        className="w-full bg-gray-900/50 border border-gray-600 rounded-lg px-4 py-2 text-white focus:border-red-500 focus:outline-none transition"
                                        value={testConfig.target_service}
                                        onChange={(e) => setTestConfig({...testConfig, target_service: e.target.value})}
                                        disabled={disableControls}
                                    >
                                        <option value="anthropic">🤖 Anthropic (Claude)</option>
                                        <option value="openai">🧠 OpenAI (GPT)</option>
                                        <option value="azure_openai">☁️ Azure OpenAI</option>
                                    </select>
                                </div>
                                
                                {/* API Key */}
                                <div>
                                    <label className="block text-sm font-medium mb-2 text-gray-300">
                                        <i className="fas fa-key mr-1 text-yellow-400"></i>API Key
                                    </label>
                                    <input
                                        type="password"
                                        className="w-full bg-gray-900/50 border border-gray-600 rounded-lg px-4 py-2 text-white focus:border-red-500 focus:outline-none transition"
                                        placeholder="sk-..."
                                        value={testConfig.api_key}
                                        onChange={(e) => setTestConfig({...testConfig, api_key: e.target.value})}
                                        disabled={disableControls}
                                    />
                                    {selectedEndpoint && (
                                        <p className="text-xs text-gray-400 mt-1">
                                            API key is stored on the server for this preset; override here if needed.
                                        </p>
                                    )}
                                </div>
                                
                                {/* Model */}
                                <div>
                                    <label className="block text-sm font-medium mb-2 text-gray-300">
                                        <i className="fas fa-brain mr-1 text-purple-400"></i>Model (optional)
                                    </label>
                                    <input
                                        type="text"
                                        className="w-full bg-gray-900/50 border border-gray-600 rounded-lg px-4 py-2 text-white focus:border-red-500 focus:outline-none transition"
                                        placeholder="Default model"
                                        value={testConfig.model}
                                        onChange={(e) => setTestConfig({...testConfig, model: e.target.value})}
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
                                            onChange={(e) => setTestConfig({...testConfig, endpoint_url: e.target.value})}
                                            disabled={disableControls}
                                        />
                                    </div>
                                )}
                                
                                {/* Test Categories */}
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
                                    {selectedPreset && (
                                        <span className="text-xs text-gray-400 self-center">
                                            {selectedPreset.description || 'Preset loaded from secure config'}
                                        </span>
                                    )}
                                </div>
                                <div className="space-y-2">
                                    {payloadCategoriesError && (
                                        <p className="text-xs text-yellow-400">{payloadCategoriesError}</p>
                                    )}
                                    <div className="space-y-2">
                                        {payloadCategories.length === 0 ? (
                                            <div className="p-3 bg-gray-900/30 rounded text-sm text-gray-400 border border-gray-700/50">
                                                No payload categories are available.
                                            </div>
                                        ) : (
                                            payloadCategories.map((category) => (
                                                <label
                                                    key={category.id}
                                                    className="flex items-center p-2 bg-gray-900/30 rounded hover:bg-gray-900/50 transition cursor-pointer"
                                                >
                                                    <input
                                                        type="checkbox"
                                                        className="mr-3 w-4 h-4 text-red-600 rounded focus:ring-red-500"
                                                        checked={testConfig.test_categories.includes(category.id)}
                                                        onChange={() => toggleCategorySelection(category.id)}
                                                        disabled={disableControls}
                                                    />
                                                    <div>
                                                        <div className="font-medium flex items-center gap-2">
                                                            <span>{category.name}</span>
                                                            <span className="text-[10px] text-gray-500 bg-gray-800 px-2 py-0.5 rounded-full">
                                                                {category.count} payloads
                                                            </span>
                                                        </div>
                                                        <div className="text-xs text-gray-400">{category.description}</div>
                                                    </div>
                                                </label>
                                            ))
                                        )}
                                    </div>
                                </div>
                            </div>

                                {/* Custom Payloads */}
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
                                            onKeyPress={(e) => e.key === 'Enter' && addCustomPayload()}
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
                                                <div key={idx} className="flex items-center justify-between p-2 bg-gray-900/30 rounded text-sm">
                                                    <span className="truncate mr-2">{payload}</span>
                                                    <button 
                                                        onClick={() => removeCustomPayload(idx)}
                                                        disabled={disableControls}
                                                        className="text-red-400 hover:text-red-300"
                                                    >
                                                        <i className="fas fa-times"></i>
                                                    </button>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>

                                {/* Claude Skill Upload */}
                                <div className="border-t border-gray-700 pt-4">
                                    <h3 className="text-sm font-medium mb-3 text-gray-400">Claude Skill Upload</h3>
                                    <div className="space-y-3">
                                        <label className="block text-sm font-medium text-gray-300">
                                            <i className="fas fa-file-zipper mr-1 text-blue-300"></i>Upload .skill or .zip
                                        </label>
                                        <input
                                            type="file"
                                            accept=".skill,.zip"
                                            className="w-full text-sm text-gray-300 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:bg-gray-700 file:text-gray-200 hover:file:bg-gray-600"
                                            onChange={handleSkillFileChange}
                                            disabled={disableControls || isScanningSkill}
                                        />
                                        <button
                                            onClick={scanSkillFile}
                                            disabled={disableControls || isScanningSkill || !skillFile}
                                            className={`w-full py-2 rounded-lg text-sm font-semibold transition border border-blue-600/60 bg-blue-700/70 hover:bg-blue-600/80 ${disableControls || isScanningSkill || !skillFile ? 'opacity-60 cursor-not-allowed' : ''}`}
                                        >
                                            <i className={`fas ${isScanningSkill ? 'fa-spinner fa-spin' : 'fa-shield-alt'} mr-2`}></i>
                                            {isScanningSkill ? 'Scanning…' : 'Scan Skill Bundle'}
                                        </button>
                                        {skillScanError && (
                                            <p className="text-xs text-yellow-400">{skillScanError}</p>
                                        )}
                                        {skillScanResult && (
                                            <div className="bg-gray-900/40 border border-gray-700/60 rounded-lg p-3 text-xs text-gray-300 space-y-2">
                                                <div className="flex items-center justify-between">
                                                    <span className="font-semibold text-gray-200">{skillScanResult.filename}</span>
                                                    <span className={`px-2 py-1 rounded-full text-[10px] uppercase tracking-wide ${skillScanResult.summary.total_findings > 0 ? 'bg-red-600/40 text-red-200' : 'bg-green-600/30 text-green-200'}`}>
                                                        {skillScanResult.summary.total_findings > 0 ? 'Findings' : 'Clean'}
                                                    </span>
                                                </div>
                                                <div className="flex flex-wrap gap-2 text-[11px] text-gray-400">
                                                    <span>Total files: {skillScanResult.summary.total_files}</span>
                                                    <span>Flagged: {skillScanResult.summary.flagged_files}</span>
                                                    <span>Findings: {skillScanResult.summary.total_findings}</span>
                                                </div>
                                                {skillScanResult.warnings?.length > 0 && (
                                                    <ul className="list-disc list-inside text-yellow-400">
                                                        {skillScanResult.warnings.map((warning, idx) => (
                                                            <li key={idx}>{warning}</li>
                                                        ))}
                                                    </ul>
                                                )}
                                                <div className="space-y-2 max-h-40 overflow-y-auto">
                                                    {skillScanResult.files.map((item, idx) => (
                                                        <div key={idx} className="border border-gray-800/70 rounded-md p-2">
                                                            <div className="flex items-center justify-between">
                                                                <span className="text-gray-200 truncate">{item.path}</span>
                                                                {item.skipped ? (
                                                                    <span className="text-[10px] text-gray-500">Skipped</span>
                                                                ) : item.findings.length > 0 ? (
                                                                    <span className="text-[10px] text-red-300">{item.findings.length} findings</span>
                                                                ) : (
                                                                    <span className="text-[10px] text-green-300">No findings</span>
                                                                )}
                                                            </div>
                                                            {item.reason && (
                                                                <p className="text-[10px] text-gray-500">{item.reason}</p>
                                                            )}
                                                            {item.findings.length > 0 && (
                                                                <ul className="mt-1 space-y-1 text-[11px] text-gray-400">
                                                                    {item.findings.map((finding, findingIdx) => (
                                                                        <li key={findingIdx}>
                                                                            <span className="text-gray-200">{finding.id}</span>
                                                                            {' '}({finding.severity}) - {finding.description}
                                                                        </li>
                                                                    ))}
                                                                </ul>
                                                            )}
                                                        </div>
                                                    ))}
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                </div>

                                {/* Advanced Settings */}
                                <div className="border-t border-gray-700 pt-4">
                                    <h3 className="text-sm font-medium mb-3 text-gray-400">Advanced Settings</h3>
                                    <div className="grid grid-cols-2 gap-3">
                                        <div>
                                            <label className="block text-xs mb-1 text-gray-400">Max Requests</label>
                                            <input
                                                type="number"
                                                className="w-full bg-gray-900/50 border border-gray-600 rounded px-3 py-1 text-white text-sm focus:border-red-500 focus:outline-none"
                                                value={testConfig.max_requests}
                                                onChange={handleMaxRequestsChange}
                                                disabled={disableControls}
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-xs mb-1 text-gray-400">Delay (sec)</label>
                                            <input
                                                type="number"
                                                step="0.1"
                                                className="w-full bg-gray-900/50 border border-gray-600 rounded px-3 py-1 text-white text-sm focus:border-red-500 focus:outline-none"
                                                value={testConfig.delay_between_requests}
                                                onChange={handleDelayChange}
                                                disabled={disableControls}
                                            />
                                        </div>
                                    </div>
                                </div>
                                
                                {/* Action Buttons */}
                                <div className="pt-4 space-y-2">
                                    {!isRunning ? (
                                        <button
                                            onClick={startTest}
                                            disabled={isShuttingDown}
                                            className={`w-full py-3 bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 rounded-lg font-bold transition transform hover:scale-105 shadow-lg ${isShuttingDown ? 'opacity-60 cursor-not-allowed' : ''}`}
                                        >
                                            <i className="fas fa-rocket mr-2"></i>Launch Attack
                                        </button>
                                    ) : (
                                        <button
                                            onClick={stopTest}
                                            disabled={isShuttingDown}
                                            className={`w-full py-3 bg-gray-600 hover:bg-gray-700 rounded-lg font-bold transition ${isShuttingDown ? 'opacity-60 cursor-not-allowed' : ''}`}
                                        >
                                            <i className="fas fa-stop mr-2"></i>Stop Test
                                        </button>
                                    )}
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    {/* Results Panel */}
                    <div className="xl:col-span-2">
                        <div className="bg-gray-800/90 backdrop-blur rounded-xl p-6 shadow-2xl border border-gray-700/50">
                            <div className="flex items-center justify-between mb-6">
                                <h2 className="text-xl font-bold text-green-400 flex items-center">
                                    <i className="fas fa-chart-line mr-2"></i>Security Assessment Results
                                </h2>
                                {session && session.status === 'completed' && (
                                    <div className="flex gap-2">
                                        <button 
                                            onClick={() => downloadReport('html')}
                                            className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg text-sm transition"
                                        >
                                            <i className="fas fa-file-code mr-1"></i>HTML Report
                                        </button>
                                        <button 
                                            onClick={() => downloadReport('json')}
                                            className="bg-purple-600 hover:bg-purple-700 px-4 py-2 rounded-lg text-sm transition"
                                        >
                                            <i className="fas fa-file-export mr-1"></i>JSON Export
                                        </button>
                                        <button 
                                            onClick={() => downloadReport('csv')}
                                            className="bg-green-600 hover:bg-green-700 px-4 py-2 rounded-lg text-sm transition"
                                        >
                                            <i className="fas fa-file-csv mr-1"></i>CSV Export
                                        </button>
                                    </div>
                                )}
                            </div>
                            
                            {/* Progress Bar */}
                            {session && isRunning && (
                                <div className="mb-6">
                                    <div className="flex justify-between text-sm mb-2">
                                        <span className="text-gray-400">Testing Progress</span>
                                        <span className="text-white font-medium">{session.progress} / {session.total_tests}</span>
                                    </div>
                                    <div className="w-full bg-gray-900/50 rounded-full h-3 overflow-hidden">
                                        <div 
                                            className="bg-gradient-to-r from-green-500 to-green-600 h-3 rounded-full transition-all duration-500 relative"
                                            style={{ width: `${(session.progress / session.total_tests) * 100}%` }}
                                        >
                                            <div className="absolute inset-0 bg-white/20 animate-pulse"></div>
                                        </div>
                                    </div>
                                </div>
                            )}
                            
                            {/* Summary Stats */}
                            {session && session.summary && (
                                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                                    <div className="bg-gradient-to-br from-blue-900/50 to-blue-800/30 rounded-lg p-4 border border-blue-600/30">
                                        <div className="flex items-center justify-between">
                                            <div>
                                                <div className="text-3xl font-bold text-blue-400">{session.summary.total_tests}</div>
                                                <div className="text-sm text-gray-400">Total Tests</div>
                                            </div>
                                            <i className="fas fa-vials text-blue-400/30 text-3xl"></i>
                                        </div>
                                    </div>
                                    <div className="bg-gradient-to-br from-red-900/50 to-red-800/30 rounded-lg p-4 border border-red-600/30">
                                        <div className="flex items-center justify-between">
                                            <div>
                                                <div className="text-3xl font-bold text-red-400">{session.summary.vulnerabilities_detected}</div>
                                                <div className="text-sm text-gray-400">Vulnerabilities</div>
                                            </div>
                                            <i className="fas fa-bug text-red-400/30 text-3xl"></i>
                                        </div>
                                    </div>
                                    <div className="bg-gradient-to-br from-yellow-900/50 to-yellow-800/30 rounded-lg p-4 border border-yellow-600/30">
                                        <div className="flex items-center justify-between">
                                            <div>
                                                <div className="text-3xl font-bold text-yellow-400">{session.summary.detection_rate}</div>
                                                <div className="text-sm text-gray-400">Detection Rate</div>
                                            </div>
                                            <i className="fas fa-percentage text-yellow-400/30 text-3xl"></i>
                                        </div>
                                    </div>
                                </div>
                            )}
                            
                            {/* Test Results Table */}
                            <div className="bg-gray-900/50 rounded-lg p-4 max-h-[600px] overflow-y-auto">
                                {results.length > 0 ? (
                                    <div className="space-y-2">
                                        {results.map((result, idx) => (
                                            <div key={idx} className={`p-4 rounded-lg border transition-all hover:shadow-lg ${
                                                result.detected 
                                                    ? 'bg-red-900/20 border-red-600/50 hover:border-red-500' 
                                                    : 'bg-gray-800/50 border-gray-700/50 hover:border-gray-600'
                                            }`}>
                                                <div className="flex items-start justify-between">
                                                    <div className="flex-1">
                                                        <div className="flex items-center gap-2 mb-2">
                                                            <span className={`px-2 py-1 rounded text-xs font-medium ${
                                                                result.category === 'baseline' ? 'bg-blue-600/30 text-blue-300' :
                                                                result.category === 'policy' ? 'bg-purple-600/30 text-purple-300' :
                                                                'bg-gray-600/30 text-gray-300'
                                                            }`}>
                                                                {result.category}
                                                            </span>
                                                            {result.detected && (
                                                                <span className="px-2 py-1 bg-red-600/30 text-red-300 rounded text-xs font-medium animate-pulse">
                                                                    <i className="fas fa-exclamation-triangle mr-1"></i>DETECTED
                                                                </span>
                                                            )}
                                                        </div>
                                                        <div className="text-sm font-mono text-gray-300 mb-1">
                                                            {result.payload.substring(0, 150)}{result.payload.length > 150 && '...'}
                                                        </div>
                                                        {result.detected && (
                                                            <div className="text-xs text-red-400 mt-1">
                                                                <i className="fas fa-flag mr-1"></i>
                                                                Triggered: {Object.keys(result.flags).filter(k => result.flags[k]).join(', ')}
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
        </div>
    );
}

function Root() {
    const [page, setPage] = useState('home');

    if (page === 'home') {
        return <Home onLaunch={() => setPage('console')} />;
    }

    return <App onBack={() => setPage('home')} />;
}

// Render the app
ReactDOM.render(<Root />, document.getElementById('root'));
