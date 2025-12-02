type HomeProps = {
    onLaunch: () => void;
};

const Home = ({ onLaunch }: HomeProps) => {
    return (
        <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-900 text-white relative overflow-hidden">
            <div className="fixed inset-0 overflow-hidden pointer-events-none">
                <div className="absolute -top-32 -left-24 w-96 h-96 bg-red-700/30 rounded-full blur-3xl animate-pulse"></div>
                <div className="absolute -bottom-32 -right-24 w-96 h-96 bg-purple-700/30 rounded-full blur-3xl animate-pulse"></div>
            </div>

            <header className="relative bg-black/60 backdrop-blur-lg border-b border-red-700/40 shadow-2xl">
                <div className="container mx-auto px-6 py-6 flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
                    <div className="flex items-center space-x-4">
                        <img src="/images/logo.png" alt="DAF-TECH logo" className="h-14 w-14 rounded-xl shadow-2xl bg-gray-900/80 border border-gray-700" />
                        <div>
                            <h1 className="text-3xl md:text-4xl font-bold flex items-center space-x-2">
                                <span className="text-white drop-shadow-lg">Injecticide</span>
                                <span className="text-xs font-semibold uppercase tracking-widest text-gray-300 bg-red-900/50 border border-red-700/50 px-2 py-1 rounded-md">DAF-TECH</span>
                            </h1>
                            <p className="text-gray-300 text-base">Enterprise LLM Security Testing Platform</p>
                        </div>
                    </div>
                    <div className="flex items-center space-x-3">
                        <span className="hidden md:inline-flex items-center text-gray-300 text-sm bg-gray-800/70 border border-gray-700/60 px-3 py-2 rounded-lg shadow-lg">
                            <i className="fas fa-moon text-red-400 mr-2"></i>
                            Dark theme optimized for secure operations
                        </span>
                        <button
                            onClick={onLaunch}
                            className="px-5 py-3 rounded-lg text-sm font-semibold transition bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-700 shadow-xl border border-red-500/60"
                        >
                            <i className="fas fa-rocket mr-2"></i>
                            Launch Testing Console
                        </button>
                    </div>
                </div>
            </header>

            <main className="relative container mx-auto px-6 py-12 space-y-10">
                <section className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-start">
                    <div className="lg:col-span-2 bg-gray-900/80 border border-gray-800 shadow-2xl rounded-2xl p-8 backdrop-blur">
                        <p className="text-sm uppercase tracking-[0.3em] text-red-400 mb-4">Enterprise Grade Defense</p>
                        <h2 className="text-4xl md:text-5xl font-black leading-tight text-white drop-shadow">
                            Secure your LLM stack against prompt injection, data leaks, and policy drift.
                        </h2>
                        <p className="mt-6 text-lg text-gray-300 leading-relaxed">
                            Injecticide streamlines adversarial testing with curated payloads, automated validation, and live reporting—purpose-built for security teams safeguarding generative AI deployments.
                        </p>
                        <div className="mt-8 flex flex-wrap gap-4">
                            <span className="px-4 py-2 rounded-full text-sm bg-gray-800/80 border border-gray-700 text-gray-200 shadow-lg">Prompt injection testing</span>
                            <span className="px-4 py-2 rounded-full text-sm bg-gray-800/80 border border-gray-700 text-gray-200 shadow-lg">Policy validation</span>
                            <span className="px-4 py-2 rounded-full text-sm bg-gray-800/80 border border-gray-700 text-gray-200 shadow-lg">Endpoint hardening</span>
                            <span className="px-4 py-2 rounded-full text-sm bg-gray-800/80 border border-gray-700 text-gray-200 shadow-lg">Automated reporting</span>
                        </div>
                    </div>
                    <div className="bg-gradient-to-b from-gray-900/90 to-black/80 border border-gray-800 shadow-2xl rounded-2xl p-6">
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="text-xl font-semibold text-white">Platform Snapshot</h3>
                            <span className="text-xs text-gray-400 uppercase tracking-wide">Live-ready</span>
                        </div>
                        <div className="space-y-4 text-gray-300">
                            <div className="flex items-center justify-between p-4 bg-gray-800/60 rounded-xl border border-gray-700/70 shadow-inner">
                                <div className="flex items-center space-x-3">
                                    <span className="p-3 rounded-lg bg-red-900/40 border border-red-700/50 text-red-300">
                                        <i className="fas fa-biohazard"></i>
                                    </span>
                                    <div>
                                        <p className="text-sm text-gray-400">Payload library</p>
                                        <p className="text-lg font-semibold text-white">Continuously updated</p>
                                    </div>
                                </div>
                                <i className="fas fa-check-circle text-green-400 text-2xl"></i>
                            </div>
                            <div className="flex items-center justify-between p-4 bg-gray-800/60 rounded-xl border border-gray-700/70 shadow-inner">
                                <div className="flex items-center space-x-3">
                                    <span className="p-3 rounded-lg bg-purple-900/40 border border-purple-700/50 text-purple-200">
                                        <i className="fas fa-shield-alt"></i>
                                    </span>
                                    <div>
                                        <p className="text-sm text-gray-400">Policy validation</p>
                                        <p className="text-lg font-semibold text-white">Streamlined reviews</p>
                                    </div>
                                </div>
                                <i className="fas fa-chart-line text-sky-400 text-2xl"></i>
                            </div>
                            <div className="flex items-center justify-between p-4 bg-gray-800/60 rounded-xl border border-gray-700/70 shadow-inner">
                                <div className="flex items-center space-x-3">
                                    <span className="p-3 rounded-lg bg-amber-900/40 border border-amber-700/50 text-amber-200">
                                        <i className="fas fa-laptop-code"></i>
                                    </span>
                                    <div>
                                        <p className="text-sm text-gray-400">Integration ready</p>
                                        <p className="text-lg font-semibold text-white">Endpoints & reports</p>
                                    </div>
                                </div>
                                <i className="fas fa-plug text-amber-400 text-2xl"></i>
                            </div>
                        </div>
                    </div>
                </section>

                <section className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="bg-gray-900/80 rounded-2xl border border-gray-800 p-6 shadow-xl">
                        <div className="w-12 h-12 rounded-xl bg-red-900/40 border border-red-700/50 flex items-center justify-center text-red-300 text-xl mb-4">
                            <i className="fas fa-syringe"></i>
                        </div>
                        <h3 className="text-xl font-semibold text-white mb-2">Advanced Prompt Testing</h3>
                        <p className="text-gray-300 leading-relaxed">Run curated adversarial prompts, automate retries, and surface risky behaviors across your LLM endpoints.</p>
                    </div>
                    <div className="bg-gray-900/80 rounded-2xl border border-gray-800 p-6 shadow-xl">
                        <div className="w-12 h-12 rounded-xl bg-purple-900/40 border border-purple-700/50 flex items-center justify-center text-purple-200 text-xl mb-4">
                            <i className="fas fa-clipboard-check"></i>
                        </div>
                        <h3 className="text-xl font-semibold text-white mb-2">Policy Validation</h3>
                        <p className="text-gray-300 leading-relaxed">Verify guardrails, monitor response integrity, and document compliance for enterprise stakeholders.</p>
                    </div>
                    <div className="bg-gray-900/80 rounded-2xl border border-gray-800 p-6 shadow-xl">
                        <div className="w-12 h-12 rounded-xl bg-emerald-900/40 border border-emerald-700/50 flex items-center justify-center text-emerald-200 text-xl mb-4">
                            <i className="fas fa-satellite-dish"></i>
                        </div>
                        <h3 className="text-xl font-semibold text-white mb-2">Operational Insights</h3>
                        <p className="text-gray-300 leading-relaxed">Track sessions, export reports, and keep teams aligned with clear telemetry and next-step guidance.</p>
                    </div>
                </section>
            </main>
        </div>
    );
};

// @ts-ignore - expose globally for inline Babel runtime
window.Home = Home;
