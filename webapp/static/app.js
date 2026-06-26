const { useState, useEffect, useRef } = React;

const FREE_EMAIL_DOMAINS = new Set([
    'gmail.com',
    'yahoo.com',
    'hotmail.com',
    'outlook.com',
    'icloud.com',
    'aol.com',
    'proton.me',
    'protonmail.com',
]);

const SECURITY_CATEGORIES = new Set(['prompt', 'code', 'enterprise', 'obfuscation']);
const REGULATED_FINDING_PREFIXES = ['pii_', 'phi_'];

function summarizeFileFindings(findings) {
    const actionable = findings.filter((finding) => finding.is_actionable !== false);
    const documentedPatterns = findings.filter((finding) => finding.display_kind === 'documented_pattern');
    const informationalSignals = findings.filter(
        (finding) => finding.display_kind === 'informational_signal'
    );

    return {
        actionableCount: actionable.length,
        documentedPatternCount: documentedPatterns.length,
        informationalSignalCount: informationalSignals.length,
    };
}

function classifyReviewClass(finding, artifactRole = 'active') {
    if (finding.tier === 'block') {
        return 'security_risk';
    }

    if (finding.display_kind === 'documented_pattern') {
        return 'documented_pattern';
    }

    if (finding.display_kind === 'informational_signal' || finding.severity === 'info') {
        return 'informational';
    }

    if (
        finding.tier !== 'review' && (
        SECURITY_CATEGORIES.has(finding.category) ||
        ['execution_intent', 'execution_primitive', 'connector_risk', 'policy_override', 'disclosure_request'].includes(finding.finding_category)
        )
    ) {
        return 'security_risk';
    }

    if (REGULATED_FINDING_PREFIXES.some((prefix) => String(finding.id || '').startsWith(prefix))) {
        if (finding.id === 'pii_email_address') {
            const emailDomains = extractEmailDomains(finding.samples || []);
            if (artifactRole === 'reference' && emailDomains.length === 1 && !FREE_EMAIL_DOMAINS.has(emailDomains[0])) {
                return 'expected_internal';
            }
        }

        if (finding.id === 'pii_phone_number' && artifactRole === 'reference') {
            return 'expected_internal';
        }

        return 'sensitive_data';
    }

    return finding.is_actionable === false ? 'informational' : 'review';
}

function extractEmailDomains(samples) {
    const domains = new Set();
    (samples || []).forEach((sample) => {
        const matches = String(sample).match(/[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})/gi) || [];
        matches.forEach((email) => {
            const domain = email.split('@')[1]?.toLowerCase();
            if (domain) {
                domains.add(domain);
            }
        });
    });
    return Array.from(domains);
}

function classifyFindingLabel(reviewClass) {
    switch (reviewClass) {
        case 'security_risk':
            return 'Security Risk';
        case 'sensitive_data':
            return 'Sensitive Data';
        case 'expected_internal':
            return 'Expected/Internal';
        case 'documented_pattern':
            return 'Documented Pattern';
        case 'informational':
            return 'Informational';
        default:
            return 'Needs Review';
    }
}

function findingPillClass(reviewClass) {
    switch (reviewClass) {
        case 'security_risk':
            return 'bg-red-600/40 text-red-200';
        case 'sensitive_data':
            return 'bg-yellow-600/30 text-yellow-200';
        case 'expected_internal':
            return 'bg-blue-600/30 text-blue-200';
        case 'documented_pattern':
            return 'bg-indigo-600/30 text-indigo-200';
        case 'informational':
            return 'bg-gray-700/70 text-gray-300';
        default:
            return 'bg-gray-700/70 text-gray-200';
    }
}

function summarizeReviewClasses(scanResult) {
    const summary = {
        security_risk: 0,
        sensitive_data: 0,
        expected_internal: 0,
        documented_pattern: 0,
        informational: 0,
        review: 0,
    };

    (scanResult.files || []).forEach((item) => {
        (item.findings || []).forEach((finding) => {
            const reviewClass = classifyReviewClass(finding, item.artifact_role || 'active');
            summary[reviewClass] = (summary[reviewClass] || 0) + 1;
        });
    });

    return summary;
}

function summarizeAssessment(scanResult) {
    const reviewSummary = summarizeReviewClasses(scanResult);

    if (reviewSummary.security_risk > 0) {
        return {
            tone: 'high',
            title: 'Security risks need review',
            body: 'The scan found execution, prompt, connector, or policy risks that should be reviewed before use.',
        };
    }

    if (reviewSummary.sensitive_data > 0) {
        return {
            tone: 'medium',
            title: 'Sensitive data detected',
            body: 'The scan found regulated or personal data that may be legitimate content, but it should be reviewed in context.',
        };
    }

    if (reviewSummary.expected_internal > 0) {
        return {
            tone: 'low',
            title: 'Expected internal contact data detected',
            body: 'The scan found business contact data that appears consistent with a reference directory or internal bundle.',
        };
    }

    if (reviewSummary.review > 0) {
        return {
            tone: 'low',
            title: 'Review findings present',
            body: 'The scan found ambiguous patterns that should be reviewed, but no block-tier behavior.',
        };
    }

    if ((scanResult.summary?.info_findings || 0) > 0) {
        return {
            tone: 'low',
            title: 'Informational context only',
            body: 'The scan found reference or informational patterns, but no blocking behavior.',
        };
    }

    return {
        tone: 'clean',
        title: 'No review findings',
        body: 'The scan did not find security risks or regulated data patterns that require follow-up.',
    };
}

function assessmentClass(tone) {
    switch (tone) {
        case 'high':
            return 'border-red-700/70 bg-red-950/30 text-red-100';
        case 'medium':
            return 'border-yellow-700/70 bg-yellow-950/20 text-yellow-100';
        case 'low':
            return 'border-blue-700/70 bg-blue-950/20 text-blue-100';
        default:
            return 'border-green-700/50 bg-green-950/20 text-green-100';
    }
}

function topConcerns(scanResult, limit = 3) {
    const concerns = [];

    (scanResult.files || []).forEach((item) => {
        (item.findings || []).forEach((finding) => {
            const reviewClass = classifyReviewClass(finding, item.artifact_role || 'active');
            if (reviewClass === 'documented_pattern' || reviewClass === 'informational') {
                return;
            }

            concerns.push({
                path: item.path,
                finding,
                reviewClass,
            });
        });
    });

    const priority = {
        security_risk: 0,
        sensitive_data: 1,
        review: 2,
        expected_internal: 3,
    };
    const severityRank = { high: 0, medium: 1, low: 2, info: 3 };

    return concerns
        .sort((left, right) => {
            const classDelta = (priority[left.reviewClass] ?? 4) - (priority[right.reviewClass] ?? 4);
            if (classDelta !== 0) {
                return classDelta;
            }
            return (severityRank[left.finding.severity] ?? 4) - (severityRank[right.finding.severity] ?? 4);
        })
        .slice(0, limit);
}

function filterFindings(findings, artifactRole, filter) {
    return (findings || []).filter((finding) => {
        const reviewClass = classifyReviewClass(finding, artifactRole);
        switch (filter) {
            case 'security':
                return reviewClass === 'security_risk';
            case 'sensitive':
                return reviewClass === 'sensitive_data';
            case 'expected':
                return reviewClass === 'expected_internal';
            default:
                return true;
        }
    });
}

function slugifyFilename(name) {
    return (name || 'skill-scan')
        .toLowerCase()
        .replace(/[^a-z0-9._-]+/g, '-')
        .replace(/-+/g, '-')
        .replace(/^-|-$/g, '');
}

function formatSkillScanMarkdown(scanResult, buildInfo, reportDepth = 'summary') {
    const lines = [];
    const generatedAt = new Date().toISOString();
    const summary = scanResult.summary || {};
    const governance = scanResult.governance_profile || {};
    const risk = scanResult.risk_classification || {};
    const reviewSummary = summarizeReviewClasses(scanResult);
    const assessment = summarizeAssessment(scanResult);
    const concerns = topConcerns(scanResult);

    lines.push(`# Skill Scan Report: ${scanResult.filename}`);
    lines.push('');
    lines.push(`- Generated: ${generatedAt}`);
    lines.push(`- File type: ${scanResult.file_type}`);
    if (buildInfo?.display_version) {
        lines.push(`- Build: ${buildInfo.display_version}`);
    }
    lines.push(`- Total files: ${summary.total_files ?? 0}`);
    lines.push(`- Flagged files: ${summary.flagged_files ?? 0}`);
    lines.push(`- Review findings: ${summary.total_findings ?? 0}`);
    lines.push(`- Informational findings: ${summary.info_findings ?? 0}`);
    lines.push('');

    lines.push('## Assessment');
    lines.push('');
    lines.push(`- Headline: ${assessment.title}`);
    lines.push(`- Summary: ${assessment.body}`);
    lines.push('');

    lines.push('## Review Buckets');
    lines.push('');
    lines.push(`- Security risks: ${reviewSummary.security_risk}`);
    lines.push(`- Sensitive data: ${reviewSummary.sensitive_data}`);
    lines.push(`- Expected/internal: ${reviewSummary.expected_internal}`);
    lines.push(`- Informational only: ${reviewSummary.informational + reviewSummary.documented_pattern}`);
    lines.push('');

    if (concerns.length > 0) {
        lines.push('## Top Concerns');
        lines.push('');
        concerns.forEach((concern) => {
            lines.push(`- ${classifyFindingLabel(concern.reviewClass)}: ${concern.finding.id} in ${concern.path}`);
        });
        lines.push('');
    }

    lines.push('## Risk Classification');
    lines.push('');
    lines.push(`- Overall risk: ${risk.overall_risk || 'unknown'}`);
    lines.push(`- Recommendation: ${risk.recommendation || 'unknown'}`);
    lines.push('');

    lines.push('## Governance');
    lines.push('');
    lines.push(`- Brokered: ${governance.brokered_tokens?.decision || 'unknown'}`);
    lines.push(`- BYO: ${governance.customer_managed_keys?.decision || 'unknown'}`);
    lines.push(`- Tier: ${governance.execution_tier || 'unknown'}`);
    lines.push(`- Sandbox required: ${governance.sandbox_required ? 'yes' : 'no'}`);
    lines.push(`- Approval required: ${governance.approval_required ? 'yes' : 'no'}`);
    if (governance.policy_capabilities?.length) {
        lines.push(`- Policy capabilities: ${governance.policy_capabilities.join(', ')}`);
    }
    lines.push('');

    if (governance.decision_reasons?.length) {
        lines.push('### Governance Reasons');
        lines.push('');
        governance.decision_reasons.forEach((reason) => lines.push(`- ${reason}`));
        lines.push('');
    }

    if (scanResult.warnings?.length) {
        lines.push('## Warnings');
        lines.push('');
        scanResult.warnings.forEach((warning) => lines.push(`- ${warning}`));
        lines.push('');
    }

    if (reportDepth !== 'detailed') {
        return lines.join('\n');
    }

    lines.push('## Files');
    lines.push('');

    (scanResult.files || []).forEach((item) => {
        const fileSummary = summarizeFileFindings(item.findings || []);
        const visibleFindings = filterFindings(item.findings || [], item.artifact_role || 'active', 'all');
        lines.push(`### ${item.path}`);
        lines.push('');
        lines.push(`- Artifact role: ${item.artifact_role || 'active'}`);
        lines.push(`- Size: ${item.size ?? 0} bytes`);
        if (item.skipped) {
            lines.push(`- Status: skipped`);
            if (item.reason) {
                lines.push(`- Reason: ${item.reason}`);
            }
            lines.push('');
            return;
        }

        lines.push(`- Review findings: ${fileSummary.actionableCount}`);
        lines.push(`- Documented patterns: ${fileSummary.documentedPatternCount}`);
        lines.push(`- Informational signals: ${fileSummary.informationalSignalCount}`);
        if (item.reason) {
            lines.push(`- Note: ${item.reason}`);
        }
        lines.push('');

        if (!visibleFindings.length) {
            lines.push('No findings.');
            lines.push('');
            return;
        }

        visibleFindings.forEach((finding) => {
            const reviewClass = classifyReviewClass(finding, item.artifact_role || 'active');
            lines.push(`- **${finding.id}** (${finding.severity})`);
            lines.push(`  - Review class: ${classifyFindingLabel(reviewClass)}`);
            lines.push(`  - Description: ${finding.description}`);
            lines.push(`  - Kind: ${finding.display_kind || 'actionable_finding'}`);
            lines.push(`  - Category: ${finding.finding_category || finding.category || 'signal'}`);
            lines.push(`  - Subject: ${finding.subject || 'unknown'}`);
            lines.push(`  - Action state: ${finding.action_state || 'present'}`);
            lines.push(`  - Tier: ${finding.tier || 'review'}`);
            lines.push(`  - Disposition: ${finding.disposition || 'unknown'}`);
            if (finding.samples?.length) {
                lines.push(`  - Samples: ${finding.samples.join(' | ')}`);
            }
        });
        lines.push('');
    });

    return lines.join('\n');
}

function architectureSeverityClass(severity) {
    switch (severity) {
        case 'critical':
            return 'border-red-600/70 bg-red-950/40 text-red-100';
        case 'high':
            return 'border-orange-600/60 bg-orange-950/30 text-orange-100';
        case 'medium':
            return 'border-yellow-600/60 bg-yellow-950/20 text-yellow-100';
        default:
            return 'border-blue-600/50 bg-blue-950/20 text-blue-100';
    }
}

function ArchitectureWorkbench({ onBack, buildInfo }) {
    const [profiles, setProfiles] = useState([]);
    const [scenarios, setScenarios] = useState([]);
    const [profileId, setProfileId] = useState('');
    const [scenarioId, setScenarioId] = useState('');
    const [analysisResult, setAnalysisResult] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [isLoadingOptions, setIsLoadingOptions] = useState(true);
    const [error, setError] = useState('');

    useEffect(() => {
        const fetchArchitectureOptions = async () => {
            setIsLoadingOptions(true);
            try {
                const response = await fetch('/api/architecture/options');
                if (!response.ok) {
                    throw new Error('Failed to load architecture analysis options');
                }

                const data = await response.json();
                const profileItems = data.profiles || [];
                const scenarioItems = data.scenarios || [];
                setProfiles(profileItems);
                setScenarios(scenarioItems);
                setProfileId(profileItems[0]?.id || '');
                setScenarioId(scenarioItems[0]?.id || '');
            } catch (fetchError) {
                console.error('Architecture options error:', fetchError);
                setError(fetchError.message || 'Could not load architecture analysis options');
            } finally {
                setIsLoadingOptions(false);
            }
        };

        fetchArchitectureOptions();
    }, []);

    const runAnalysis = async () => {
        if (!profileId || !scenarioId) {
            setError('Select a profile and scenario to analyze.');
            return;
        }

        setError('');
        setIsLoading(true);

        try {
            const response = await fetch('/api/architecture/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    profile_id: profileId,
                    scenario_id: scenarioId,
                }),
            });

            if (!response.ok) {
                const details = await response.json().catch(() => ({}));
                throw new Error(details?.detail || 'Architecture analysis failed');
            }

            const data = await response.json();
            setAnalysisResult(data);
        } catch (analysisError) {
            console.error('Architecture analysis failed:', analysisError);
            setError(analysisError.message || 'Architecture analysis failed');
        } finally {
            setIsLoading(false);
        }
    };

    const activeScenario = scenarios.find((scenario) => scenario.id === scenarioId);
    const findings = analysisResult?.trace?.findings || [];
    const crossings = analysisResult?.trace?.boundary_crossings || [];
    const edges = analysisResult?.trace?.edges || [];

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-950 via-cyan-950 to-black text-white">
            <div className="fixed inset-0 overflow-hidden pointer-events-none">
                <div className="absolute top-0 right-0 w-[34rem] h-[34rem] bg-cyan-600/10 rounded-full blur-3xl"></div>
                <div className="absolute bottom-0 left-0 w-[28rem] h-[28rem] bg-red-600/10 rounded-full blur-3xl"></div>
            </div>

            <header className="relative border-b border-cyan-800/40 bg-black/40 backdrop-blur">
                <div className="container mx-auto px-6 py-5 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                    <div>
                        <div className="flex items-center gap-3">
                            <span className="inline-flex h-12 w-12 items-center justify-center rounded-2xl border border-cyan-700/40 bg-cyan-900/30 text-cyan-200">
                                <i className="fas fa-diagram-project"></i>
                            </span>
                            <div>
                                <h1 className="text-3xl font-bold text-white">Architecture Analysis</h1>
                                <p className="text-sm text-cyan-100/80">Trace risky paths across prompts, retrieval, tools, memory, connectors, and outputs.</p>
                            </div>
                        </div>
                    </div>
                    <div className="flex flex-wrap items-center gap-3">
                        {buildInfo && (
                            <span className="inline-flex items-center text-[11px] text-gray-300 bg-gray-900/60 border border-gray-700/60 px-2 py-1 rounded-md">
                                <i className="fas fa-code-branch text-cyan-300 mr-2"></i>
                                {buildInfo.display_version}
                            </span>
                        )}
                        <button
                            onClick={onBack}
                            className="px-4 py-2 rounded-lg text-sm font-semibold transition border border-gray-600/70 bg-gray-800/70 hover:bg-gray-700/80 text-gray-200"
                        >
                            <i className="fas fa-arrow-left mr-2"></i>
                            Back to Overview
                        </button>
                    </div>
                </div>
            </header>

            <main className="relative container mx-auto px-6 py-8">
                <div className="grid grid-cols-1 xl:grid-cols-[360px_minmax(0,1fr)] gap-8">
                    <section className="space-y-6">
                        <div className="rounded-2xl border border-cyan-800/40 bg-slate-950/70 p-6 shadow-2xl">
                            <p className="text-xs uppercase tracking-[0.3em] text-cyan-300 mb-3">Modeled Input</p>
                            <h2 className="text-xl font-semibold mb-4">Analysis Setup</h2>

                            <div className="space-y-4">
                                <div>
                                    <label className="block text-xs mb-2 text-gray-400">Architecture Profile</label>
                                    <select
                                        value={profileId}
                                        onChange={(event) => setProfileId(event.target.value)}
                                        disabled={isLoadingOptions || isLoading}
                                        className="w-full rounded-lg border border-gray-700 bg-gray-950/80 px-3 py-2 text-sm text-white focus:border-cyan-500 focus:outline-none"
                                    >
                                        {profiles.map((profile) => (
                                            <option key={profile.id} value={profile.id}>
                                                {profile.name}
                                            </option>
                                        ))}
                                    </select>
                                </div>

                                <div>
                                    <label className="block text-xs mb-2 text-gray-400">Scenario</label>
                                    <select
                                        value={scenarioId}
                                        onChange={(event) => setScenarioId(event.target.value)}
                                        disabled={isLoadingOptions || isLoading}
                                        className="w-full rounded-lg border border-gray-700 bg-gray-950/80 px-3 py-2 text-sm text-white focus:border-cyan-500 focus:outline-none"
                                    >
                                        {scenarios.map((scenario) => (
                                            <option key={scenario.id} value={scenario.id}>
                                                {scenario.name}
                                            </option>
                                        ))}
                                    </select>
                                </div>

                                <button
                                    onClick={runAnalysis}
                                    disabled={isLoadingOptions || isLoading || !profileId || !scenarioId}
                                    className={`w-full rounded-lg border px-4 py-3 text-sm font-semibold transition ${
                                        isLoadingOptions || isLoading || !profileId || !scenarioId
                                            ? 'cursor-not-allowed border-gray-700 bg-gray-800/60 text-gray-400'
                                            : 'border-cyan-500/60 bg-cyan-700/80 text-white hover:bg-cyan-600/80'
                                    }`}
                                >
                                    <i className={`mr-2 fas ${isLoading ? 'fa-spinner fa-spin' : 'fa-wave-square'}`}></i>
                                    {isLoading ? 'Analyzing Path' : 'Run Architecture Analysis'}
                                </button>
                            </div>

                            {error && (
                                <div className="mt-4 rounded-xl border border-red-800/60 bg-red-950/30 px-4 py-3 text-sm text-red-100">
                                    {error}
                                </div>
                            )}
                        </div>

                        <div className="rounded-2xl border border-gray-800 bg-black/40 p-6 shadow-2xl">
                            <p className="text-xs uppercase tracking-[0.3em] text-gray-400 mb-3">Current Scenario</p>
                            {activeScenario ? (
                                <div className="space-y-3">
                                    <h3 className="text-lg font-semibold text-white">{activeScenario.name}</h3>
                                    <p className="text-sm leading-relaxed text-gray-300">{activeScenario.description}</p>
                                    <div className="flex flex-wrap gap-2 text-xs">
                                        <span className="rounded-full border border-cyan-700/40 bg-cyan-950/30 px-3 py-1 text-cyan-100">
                                            Entry: {activeScenario.entry_point}
                                        </span>
                                        <span className="rounded-full border border-orange-700/40 bg-orange-950/20 px-3 py-1 text-orange-100">
                                            Class: {activeScenario.category.replaceAll('_', ' ')}
                                        </span>
                                    </div>
                                </div>
                            ) : (
                                <p className="text-sm text-gray-400">Select a scenario to see its modeled path.</p>
                            )}
                        </div>
                    </section>

                    <section className="space-y-6">
                        {analysisResult ? (
                            <>
                                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                                    <div className="rounded-2xl border border-gray-800 bg-black/40 p-5">
                                        <p className="text-xs uppercase tracking-[0.3em] text-gray-400 mb-2">Severity</p>
                                        <div className="text-3xl font-black text-white">{analysisResult.summary.highest_severity}</div>
                                        <p className="mt-2 text-sm text-gray-300">Highest modeled path severity for this scenario.</p>
                                    </div>
                                    <div className="rounded-2xl border border-gray-800 bg-black/40 p-5">
                                        <p className="text-xs uppercase tracking-[0.3em] text-gray-400 mb-2">Boundary Crossings</p>
                                        <div className="text-3xl font-black text-white">{analysisResult.summary.boundary_crossing_count}</div>
                                        <p className="mt-2 text-sm text-gray-300">Trust, privilege, or memory boundaries crossed.</p>
                                    </div>
                                    <div className="rounded-2xl border border-gray-800 bg-black/40 p-5">
                                        <p className="text-xs uppercase tracking-[0.3em] text-gray-400 mb-2">Findings</p>
                                        <div className="text-3xl font-black text-white">{analysisResult.summary.finding_count}</div>
                                        <p className="mt-2 text-sm text-gray-300">Deterministic findings derived from the path.</p>
                                    </div>
                                </div>

                                <div className="rounded-2xl border border-cyan-800/30 bg-slate-950/70 p-6 shadow-2xl">
                                    <div className="flex items-center justify-between gap-4 flex-wrap">
                                        <div>
                                            <p className="text-xs uppercase tracking-[0.3em] text-cyan-300 mb-2">Path Overview</p>
                                            <h2 className="text-2xl font-semibold text-white">{analysisResult.scenario.name}</h2>
                                        </div>
                                        <div className="flex flex-wrap gap-2 text-xs">
                                            {analysisResult.trace.score.privileges_exposed.map((item) => (
                                                <span key={item} className="rounded-full border border-red-700/40 bg-red-950/20 px-3 py-1 text-red-100">
                                                    {item}
                                                </span>
                                            ))}
                                        </div>
                                    </div>

                                    <div className="mt-5 flex flex-wrap items-center gap-2 text-sm text-gray-300">
                                        {edges.map((edge, index) => (
                                            <React.Fragment key={`${edge.source}-${edge.target}-${index}`}>
                                                <span className="rounded-full border border-gray-700 bg-gray-950/80 px-3 py-2">{edge.source}</span>
                                                <span className="text-cyan-300"><i className="fas fa-arrow-right"></i></span>
                                                <span className="rounded-full border border-cyan-700/40 bg-cyan-950/20 px-3 py-2">{edge.target}</span>
                                            </React.Fragment>
                                        ))}
                                    </div>

                                    <div className="mt-6 grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                                        <div className="rounded-xl border border-gray-800 bg-black/30 p-4">
                                            <p className="text-xs uppercase tracking-[0.3em] text-gray-400 mb-2">Attack Entry</p>
                                            <p className="text-white font-semibold">{analysisResult.trace.score.attack_entry_point}</p>
                                        </div>
                                        <div className="rounded-xl border border-gray-800 bg-black/30 p-4">
                                            <p className="text-xs uppercase tracking-[0.3em] text-gray-400 mb-2">Propagation</p>
                                            <p className="text-white font-semibold">{analysisResult.trace.score.propagation_likelihood}</p>
                                        </div>
                                        <div className="rounded-xl border border-gray-800 bg-black/30 p-4">
                                            <p className="text-xs uppercase tracking-[0.3em] text-gray-400 mb-2">Data Sensitivity</p>
                                            <p className="text-white font-semibold">{analysisResult.trace.score.data_sensitivity}</p>
                                        </div>
                                        <div className="rounded-xl border border-gray-800 bg-black/30 p-4">
                                            <p className="text-xs uppercase tracking-[0.3em] text-gray-400 mb-2">Components Touched</p>
                                            <p className="text-white font-semibold">{analysisResult.trace.score.components_touched.join(', ')}</p>
                                        </div>
                                    </div>
                                </div>

                                <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1fr)_360px] gap-6">
                                    <div className="rounded-2xl border border-gray-800 bg-black/40 p-6 shadow-2xl">
                                        <p className="text-xs uppercase tracking-[0.3em] text-gray-400 mb-4">Path Findings</p>
                                        <div className="space-y-4">
                                            {findings.map((finding) => (
                                                <div key={finding.finding_id} className={`rounded-xl border p-4 ${architectureSeverityClass(finding.severity)}`}>
                                                    <div className="flex items-center justify-between gap-3 flex-wrap">
                                                        <h3 className="text-lg font-semibold">{finding.title}</h3>
                                                        <span className="rounded-full border border-white/10 px-3 py-1 text-xs uppercase tracking-[0.2em]">
                                                            {finding.severity}
                                                        </span>
                                                    </div>
                                                    <p className="mt-3 text-sm leading-relaxed">{finding.summary}</p>
                                                    <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                                                        <div>
                                                            <p className="text-xs uppercase tracking-[0.2em] text-white/70 mb-2">Evidence</p>
                                                            <ul className="space-y-2">
                                                                {finding.evidence.map((item, index) => (
                                                                    <li key={index} className="text-white/90">• {item}</li>
                                                                ))}
                                                            </ul>
                                                        </div>
                                                        <div>
                                                            <p className="text-xs uppercase tracking-[0.2em] text-white/70 mb-2">Controls</p>
                                                            <ul className="space-y-2">
                                                                {finding.recommended_controls.map((item, index) => (
                                                                    <li key={index} className="text-white/90">• {item}</li>
                                                                ))}
                                                            </ul>
                                                        </div>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    </div>

                                    <div className="space-y-6">
                                        <div className="rounded-2xl border border-gray-800 bg-black/40 p-6 shadow-2xl">
                                            <p className="text-xs uppercase tracking-[0.3em] text-gray-400 mb-4">Boundary Crossings</p>
                                            <div className="space-y-3">
                                                {crossings.map((crossing, index) => (
                                                    <div key={`${crossing.source}-${crossing.target}-${index}`} className="rounded-xl border border-gray-800 bg-gray-950/60 p-4">
                                                        <div className="flex items-center justify-between gap-3">
                                                            <span className="text-sm font-semibold text-white">{crossing.source} → {crossing.target}</span>
                                                            <span className={`rounded-full px-2 py-1 text-[10px] uppercase tracking-[0.2em] ${crossing.severity === 'high' ? 'bg-red-700/40 text-red-100' : crossing.severity === 'medium' ? 'bg-yellow-700/30 text-yellow-100' : 'bg-blue-700/30 text-blue-100'}`}>
                                                                {crossing.severity}
                                                            </span>
                                                        </div>
                                                        <p className="mt-2 text-xs text-cyan-200/90">{crossing.boundary_type.replaceAll('_', ' ')}</p>
                                                        <p className="mt-2 text-sm text-gray-300">{crossing.reason}</p>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>

                                        <div className="rounded-2xl border border-gray-800 bg-black/40 p-6 shadow-2xl">
                                            <p className="text-xs uppercase tracking-[0.3em] text-gray-400 mb-4">Execution Posture</p>
                                            <div className="space-y-3 text-sm text-gray-300">
                                                <p>Profile: <span className="font-semibold text-white">{analysisResult.profile.name}</span></p>
                                                <p>Scenario: <span className="font-semibold text-white">{analysisResult.scenario.category.replaceAll('_', ' ')}</span></p>
                                                <p>Focus: <span className="font-semibold text-white">Grouped tool boundaries and deterministic trust crossings</span></p>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </>
                        ) : (
                            <div className="rounded-3xl border border-dashed border-cyan-800/40 bg-black/20 p-12 text-center shadow-2xl">
                                <div className="mx-auto mb-5 flex h-20 w-20 items-center justify-center rounded-3xl border border-cyan-700/40 bg-cyan-950/20 text-cyan-200 text-3xl">
                                    <i className="fas fa-route"></i>
                                </div>
                                <h2 className="text-2xl font-semibold text-white">Modeled path review lives here</h2>
                                <p className="mt-3 text-sm leading-relaxed text-gray-400 max-w-2xl mx-auto">
                                    Select a grouped architecture profile and a scenario pack, then run analysis to surface risky trust crossings, exposed privileges, and memory or tool-path findings.
                                </p>
                            </div>
                        )}
                    </section>
                </div>
            </main>
        </div>
    );
}

function App({ onBack, buildInfo }) {
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
        delay_between_requests: 0.5,
        requests_per_minute: 60,
        requests_per_hour: 1000
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
    const [skillReportDepth, setSkillReportDepth] = useState('summary');
    const [skillFindingFilter, setSkillFindingFilter] = useState('all');

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
        const requestsPerMinuteValue = Number(testConfig.requests_per_minute);
        const requestsPerHourValue = Number(testConfig.requests_per_hour);

        if (!Number.isInteger(maxRequestsValue) || maxRequestsValue <= 0) {
            throw new Error('Please enter a valid positive integer for Max Requests.');
        }

        if (!Number.isFinite(delayValue) || delayValue < 0) {
            throw new Error('Please enter a valid non-negative number for Delay.');
        }

        if (!Number.isInteger(requestsPerMinuteValue) || requestsPerMinuteValue <= 0) {
            throw new Error('Please enter a valid positive integer for requests per minute.');
        }

        if (!Number.isInteger(requestsPerHourValue) || requestsPerHourValue <= 0) {
            throw new Error('Please enter a valid positive integer for requests per hour.');
        }

        const validatedCategories = filterToAvailableCategories(testConfig.test_categories);

        return {
            ...testConfig,
            test_categories: validatedCategories,
            max_requests: maxRequestsValue,
            delay_between_requests: delayValue,
            requests_per_minute: requestsPerMinuteValue,
            requests_per_hour: requestsPerHourValue,
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
            setResults(data.results || []);
            
            // Connect WebSocket for live updates
            const websocketProtocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
            const websocket = new WebSocket(`${websocketProtocol}://${window.location.host}/ws/${data.session_id}`);
            
            websocket.onmessage = (event) => {
                const update = JSON.parse(event.data);
                setSession(update);
                setResults(update.results || []);
                
                if (update.status === 'completed' || update.status === 'failed' || update.status === 'cancelled') {
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

        if (session?.session_id) {
            fetch(`/api/test/${session.session_id}/cancel`, { method: 'POST' })
                .catch((error) => console.error('Failed to cancel test:', error));
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
        setSkillReportDepth('summary');
        setSkillFindingFilter('all');
    };

    const handleSkillFileChange = (event) => {
        const file = event.target.files?.[0] || null;
        setSkillFile(file);
        resetSkillScanState();
    };

    const scanSkillFile = async () => {
        if (!skillFile) {
            setSkillScanError('Select a skill file, reference file, or archive to scan.');
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

    const downloadSkillScanMarkdown = () => {
        if (!skillScanResult) {
            return;
        }

        const markdown = formatSkillScanMarkdown(skillScanResult, buildInfo, skillReportDepth);
        const blob = new Blob([markdown], { type: 'text/markdown;charset=utf-8' });
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        const baseName = slugifyFilename(skillScanResult.filename || 'skill-scan');
        link.href = url;
        link.download = `${baseName}-scan-report-${skillReportDepth}.md`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
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
                                <div className="flex flex-wrap items-center gap-3">
                                    <p className="text-sm text-gray-300">Enterprise LLM Security Testing Platform</p>
                                    {buildInfo && (
                                        <span className="inline-flex items-center text-[11px] text-gray-300 bg-gray-800/70 border border-gray-700/60 px-2 py-1 rounded-md shadow-lg">
                                            <i className="fas fa-code-branch text-red-400 mr-2"></i>
                                            {buildInfo.display_version}
                                            {buildInfo.git_dirty && <span className="ml-2 text-yellow-300">dirty</span>}
                                        </span>
                                    )}
                                </div>
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
                                            <i className="fas fa-file-zipper mr-1 text-blue-300"></i>Upload SKILL.md, .skill, or .zip
                                        </label>
                                        <input
                                            type="file"
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
                                            {isScanningSkill ? 'Scanning…' : 'Scan Skill File/Bundle'}
                                        </button>
                                        {skillScanError && (
                                            <p className="text-xs text-yellow-400">{skillScanError}</p>
                                        )}
                                        {skillScanResult && (
                                            <div className="bg-gray-900/40 border border-gray-700/60 rounded-lg p-3 text-xs text-gray-300 space-y-2">
                                                {(() => {
                                                    const assessment = summarizeAssessment(skillScanResult);
                                                    const reviewSummary = summarizeReviewClasses(skillScanResult);
                                                    const concerns = topConcerns(skillScanResult);
                                                    return (
                                                        <>
                                                            <div className={`rounded-md border px-3 py-2 ${assessmentClass(assessment.tone)}`}>
                                                                <div className="text-sm font-semibold">{assessment.title}</div>
                                                                <p className="mt-1 text-[11px] opacity-90">{assessment.body}</p>
                                                                <div className="mt-2 flex flex-wrap gap-2 text-[10px]">
                                                                    <span>Security risks: {reviewSummary.security_risk}</span>
                                                                    <span>Sensitive data: {reviewSummary.sensitive_data}</span>
                                                                    <span>Expected/internal: {reviewSummary.expected_internal}</span>
                                                                </div>
                                                            </div>
                                                            {concerns.length > 0 && (
                                                                <div className="rounded-md border border-gray-800/80 bg-black/20 p-2">
                                                                    <div className="text-[10px] uppercase tracking-wide text-gray-500 mb-1">Top Concerns</div>
                                                                    <ul className="space-y-1 text-[11px] text-gray-300">
                                                                        {concerns.map((concern, concernIdx) => (
                                                                            <li key={concernIdx}>
                                                                                <span className={`inline-flex px-2 py-0.5 rounded-full text-[10px] mr-2 ${findingPillClass(concern.reviewClass)}`}>
                                                                                    {classifyFindingLabel(concern.reviewClass)}
                                                                                </span>
                                                                                {concern.finding.id} in {concern.path}
                                                                            </li>
                                                                        ))}
                                                                    </ul>
                                                                </div>
                                                            )}
                                                        </>
                                                    );
                                                })()}
                                                <div className="flex items-center justify-between">
                                                    <span className="font-semibold text-gray-200">{skillScanResult.filename}</span>
                                                    <div className="flex items-center gap-2">
                                                        <div className="flex rounded-md overflow-hidden border border-gray-700/70">
                                                            {['summary', 'detailed'].map((mode) => (
                                                                <button
                                                                    key={mode}
                                                                    onClick={() => setSkillReportDepth(mode)}
                                                                    className={`px-2 py-1 text-[10px] uppercase tracking-wide transition ${skillReportDepth === mode ? 'bg-blue-700/80 text-white' : 'bg-gray-800/80 text-gray-300 hover:bg-gray-700/80'}`}
                                                                >
                                                                    {mode}
                                                                </button>
                                                            ))}
                                                        </div>
                                                        <button
                                                            onClick={downloadSkillScanMarkdown}
                                                            className="px-2 py-1 rounded-md text-[10px] uppercase tracking-wide bg-gray-800/80 hover:bg-gray-700/80 border border-gray-700/70 text-gray-200 transition"
                                                        >
                                                            <i className="fas fa-file-arrow-down mr-1"></i>
                                                            Export {skillReportDepth === 'summary' ? 'Summary' : 'Detailed'}
                                                        </button>
                                                        <span className={`px-2 py-1 rounded-full text-[10px] uppercase tracking-wide ${skillScanResult.summary.total_findings > 0 ? 'bg-red-600/40 text-red-200' : 'bg-green-600/30 text-green-200'}`}>
                                                            {skillScanResult.summary.total_findings > 0 ? 'Review' : 'Clean'}
                                                        </span>
                                                    </div>
                                                </div>
                                                <div className="flex flex-wrap gap-2 text-[11px] text-gray-400">
                                                    <span>Total files: {skillScanResult.summary.total_files}</span>
                                                    <span>Flagged: {skillScanResult.summary.flagged_files}</span>
                                                    <span>Review findings: {skillScanResult.summary.total_findings}</span>
                                                </div>
                                                <div className="flex flex-wrap gap-2">
                                                    {[
                                                        ['all', 'All'],
                                                        ['security', 'Security Risks'],
                                                        ['sensitive', 'Sensitive Data'],
                                                        ['expected', 'Expected/Internal'],
                                                    ].map(([filterId, label]) => (
                                                        <button
                                                            key={filterId}
                                                            onClick={() => setSkillFindingFilter(filterId)}
                                                            className={`px-2 py-1 rounded-md text-[10px] uppercase tracking-wide border transition ${skillFindingFilter === filterId ? 'bg-blue-700/80 border-blue-600/60 text-white' : 'bg-gray-800/70 border-gray-700/70 text-gray-300 hover:bg-gray-700/80'}`}
                                                        >
                                                            {label}
                                                        </button>
                                                    ))}
                                                </div>
                                                {skillScanResult.governance_profile && (
                                                    <div className="rounded-md border border-gray-800/80 bg-black/20 p-2 space-y-2">
                                                        <div className="flex flex-wrap items-center gap-2">
                                                            <span className="text-[10px] uppercase tracking-wide text-gray-500">Governance</span>
                                                            <span className={`px-2 py-1 rounded-full text-[10px] uppercase tracking-wide ${
                                                                skillScanResult.governance_profile.brokered_tokens.decision === 'block_by_default'
                                                                    ? 'bg-red-600/40 text-red-200'
                                                                    : skillScanResult.governance_profile.brokered_tokens.decision === 'require_admin_approval'
                                                                        ? 'bg-yellow-600/30 text-yellow-200'
                                                                        : 'bg-green-600/30 text-green-200'
                                                            }`}>
                                                                Brokered: {skillScanResult.governance_profile.brokered_tokens.decision.replaceAll('_', ' ')}
                                                            </span>
                                                            <span className={`px-2 py-1 rounded-full text-[10px] uppercase tracking-wide ${
                                                                skillScanResult.governance_profile.customer_managed_keys.decision === 'block_by_default'
                                                                    ? 'bg-red-600/40 text-red-200'
                                                                    : skillScanResult.governance_profile.customer_managed_keys.decision === 'require_admin_approval'
                                                                        ? 'bg-yellow-600/30 text-yellow-200'
                                                                        : 'bg-blue-600/30 text-blue-200'
                                                            }`}>
                                                                BYO: {skillScanResult.governance_profile.customer_managed_keys.decision.replaceAll('_', ' ')}
                                                            </span>
                                                        </div>
                                                        <div className="flex flex-wrap gap-2 text-[11px] text-gray-400">
                                                            <span>Tier: {skillScanResult.governance_profile.execution_tier}</span>
                                                            <span>Sandbox: {skillScanResult.governance_profile.sandbox_required ? 'required' : 'not required'}</span>
                                                            <span>Approval: {skillScanResult.governance_profile.approval_required ? 'required' : 'not required'}</span>
                                                        </div>
                                                        {skillScanResult.governance_profile.policy_capabilities?.length > 0 && (
                                                            <div className="flex flex-wrap gap-1">
                                                                {skillScanResult.governance_profile.policy_capabilities.map((capability, capabilityIdx) => (
                                                                    <span key={capabilityIdx} className="px-2 py-1 rounded bg-gray-800/80 text-[10px] text-gray-300">
                                                                        {capability}
                                                                    </span>
                                                                ))}
                                                            </div>
                                                        )}
                                                        {skillScanResult.governance_profile.decision_reasons?.length > 0 && (
                                                            <ul className="list-disc list-inside text-[11px] text-gray-400">
                                                                {skillScanResult.governance_profile.decision_reasons.map((reason, idx) => (
                                                                    <li key={idx}>{reason}</li>
                                                                ))}
                                                            </ul>
                                                        )}
                                                    </div>
                                                )}
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
                                                            {(() => {
                                                                const visibleFindings = filterFindings(
                                                                    item.findings || [],
                                                                    item.artifact_role || 'active',
                                                                    skillFindingFilter
                                                                );
                                                                const summary = summarizeFileFindings(visibleFindings);
                                                                return (
                                                                    <>
                                                                        <div className="flex items-center justify-between">
                                                                            <span className="text-gray-200 truncate">{item.path}</span>
                                                                            {item.skipped ? (
                                                                                <span className="text-[10px] text-gray-500">Skipped</span>
                                                                            ) : summary.actionableCount > 0 ? (
                                                                                <span className="text-[10px] text-red-300">{summary.actionableCount} review findings</span>
                                                                            ) : summary.documentedPatternCount > 0 ? (
                                                                                <span className="text-[10px] text-blue-300">{summary.documentedPatternCount} documented patterns</span>
                                                                            ) : summary.informationalSignalCount > 0 ? (
                                                                                <span className="text-[10px] text-yellow-300">{summary.informationalSignalCount} informational signals</span>
                                                                            ) : (
                                                                                <span className="text-[10px] text-green-300">No matching findings</span>
                                                                            )}
                                                                        </div>
                                                                        {!item.skipped && (summary.documentedPatternCount > 0 || summary.informationalSignalCount > 0) && summary.actionableCount === 0 && (
                                                                            <p className="text-[10px] text-gray-500 mt-1">
                                                                                {summary.documentedPatternCount > 0
                                                                                    ? 'Reference or audit content documenting risky patterns; not treated as executable behavior.'
                                                                                    : 'Informational context only; no blocking behavior detected.'}
                                                                            </p>
                                                                        )}
                                                                    </>
                                                                );
                                                            })()}
                                                            {item.reason && (
                                                                <p className="text-[10px] text-gray-500">{item.reason}</p>
                                                            )}
                                                            {filterFindings(item.findings || [], item.artifact_role || 'active', skillFindingFilter).length > 0 && (
                                                                <ul className="mt-1 space-y-1 text-[11px] text-gray-400">
                                                                    {filterFindings(item.findings || [], item.artifact_role || 'active', skillFindingFilter).map((finding, findingIdx) => {
                                                                        const reviewClass = classifyReviewClass(finding, item.artifact_role || 'active');
                                                                        return (
                                                                        <li key={findingIdx}>
                                                                            <div className="flex flex-wrap items-center gap-2">
                                                                                <span className="text-gray-200">{finding.id}</span>
                                                                                <span className={`px-2 py-0.5 rounded-full text-[10px] ${findingPillClass(reviewClass)}`}>
                                                                                    {classifyFindingLabel(reviewClass)}
                                                                                </span>
                                                                            </div>
                                                                            {' '}({finding.severity}) - {finding.description}
                                                                            <div className="text-[10px] text-gray-500">
                                                                                {finding.finding_category} / {finding.subject} / {finding.action_state} / {finding.disposition}
                                                                            </div>
                                                                            {finding.samples?.length > 0 && skillReportDepth === 'detailed' && (
                                                                                <div className="text-[10px] text-gray-500">
                                                                                    Samples: {finding.samples.join(' | ')}
                                                                                </div>
                                                                            )}
                                                                            {finding.display_kind === 'documented_pattern' && (
                                                                                <div className="text-[10px] text-blue-300">
                                                                                    Documented pattern in reference or audit content
                                                                                </div>
                                                                            )}
                                                                            {finding.display_kind === 'informational_signal' && (
                                                                                <div className="text-[10px] text-yellow-300">
                                                                                    Informational context only
                                                                                </div>
                                                                            )}
                                                                        </li>
                                                                    );
                                                                    })}
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
                                        <div>
                                            <label className="block text-xs mb-1 text-gray-400">Req / Minute</label>
                                            <input
                                                type="number"
                                                className="w-full bg-gray-900/50 border border-gray-600 rounded px-3 py-1 text-white text-sm focus:border-red-500 focus:outline-none"
                                                value={testConfig.requests_per_minute}
                                                onChange={(e) => setTestConfig({...testConfig, requests_per_minute: Number(e.target.value)})}
                                                disabled={disableControls}
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-xs mb-1 text-gray-400">Req / Hour</label>
                                            <input
                                                type="number"
                                                className="w-full bg-gray-900/50 border border-gray-600 rounded px-3 py-1 text-white text-sm focus:border-red-500 focus:outline-none"
                                                value={testConfig.requests_per_hour}
                                                onChange={(e) => setTestConfig({...testConfig, requests_per_hour: Number(e.target.value)})}
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
                                            style={{ width: `${session.total_tests ? (session.progress / session.total_tests) * 100 : 0}%` }}
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
    const [buildInfo, setBuildInfo] = useState(null);

    useEffect(() => {
        const fetchBuildInfo = async () => {
            try {
                const response = await fetch('/api/app/version');
                if (!response.ok) {
                    throw new Error('Failed to load build info');
                }
                const data = await response.json();
                setBuildInfo(data);
            } catch (error) {
                console.error('Build info error:', error);
            }
        };

        fetchBuildInfo();
    }, []);

    if (page === 'home') {
        return (
            <Home
                onLaunchConsole={() => setPage('console')}
                onLaunchArchitecture={() => setPage('architecture')}
                buildInfo={buildInfo}
            />
        );
    }

    if (page === 'architecture') {
        return <ArchitectureWorkbench onBack={() => setPage('home')} buildInfo={buildInfo} />;
    }

    return <App onBack={() => setPage('home')} buildInfo={buildInfo} />;
}

// Render the app
ReactDOM.render(<Root />, document.getElementById('root'));
