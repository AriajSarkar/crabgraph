// ============================================================================
// CrabGraph Professional Benchmark Dashboard
// Comprehensive statistical analysis with visualization
// ============================================================================

// Performance thresholds (industry standard comparisons)
const THRESHOLDS = {
    // AEAD throughput in MB/s (compared to industry standards)
    aead: {
        hwAccelerated: 1000,  // Hardware accelerated (AES-NI)
        excellent: 500,        // Excellent software implementation
        good: 100,             // Good performance
        acceptable: 10,        // Acceptable
    },
    // Wrapper overhead (compared to raw implementations)
    overhead: {
        excellent: 10,   // < 10% (near-zero cost abstraction)
        good: 20,        // < 20% (acceptable for safety)
        acceptable: 40,  // < 40% (reasonable tradeoff)
    },
    // General timing thresholds in nanoseconds
    time: {
        ultraFast: 1000,       // < 1 µs
        veryFast: 10000,       // < 10 µs
        fast: 100000,          // < 100 µs
        acceptable: 10000000,  // < 10 ms
    },
};

// Global state
let allBenchmarkData = {
    raw: {},
    statistics: {},
    charts: {}
};

// ============================================================================
// Utility Functions
// ============================================================================

function formatTime(nanoseconds) {
    if (nanoseconds < 1000) return `${nanoseconds.toFixed(0)} ns`;
    if (nanoseconds < 1000000) return `${(nanoseconds / 1000).toFixed(2)} µs`;
    if (nanoseconds < 1000000000) return `${(nanoseconds / 1000000).toFixed(2)} ms`;
    return `${(nanoseconds / 1000000000).toFixed(2)} s`;
}

function calculateThroughput(bytes, nanoseconds) {
    const seconds = nanoseconds / 1000000000;
    const mbps = (bytes / seconds) / (1024 * 1024);
    if (mbps < 1) return { value: mbps * 1024, unit: 'KB/s', mbps: mbps };
    if (mbps < 1024) return { value: mbps, unit: 'MB/s', mbps: mbps };
    return { value: mbps / 1024, unit: 'GB/s', mbps: mbps };
}

function formatThroughput(throughput) {
    return `${throughput.value.toFixed(2)} ${throughput.unit}`;
}

function getPerformanceLevel(value, type) {
    if (type === 'throughput') {
        const mbps = typeof value === 'object' ? value.mbps : value;
        if (mbps >= THRESHOLDS.aead.hwAccelerated) return { level: 'hw-accel', label: 'HW Accelerated', color: 'purple' };
        if (mbps >= THRESHOLDS.aead.excellent) return { level: 'excellent', label: 'Excellent', color: 'green' };
        if (mbps >= THRESHOLDS.aead.good) return { level: 'good', label: 'Good', color: 'blue' };
        if (mbps >= THRESHOLDS.aead.acceptable) return { level: 'acceptable', label: 'Acceptable', color: 'yellow' };
        return { level: 'slow', label: 'Slow', color: 'red' };
    }
    
    if (type === 'overhead') {
        if (value < THRESHOLDS.overhead.excellent) return { level: 'excellent', label: 'Minimal', color: 'green' };
        if (value < THRESHOLDS.overhead.good) return { level: 'good', label: 'Low', color: 'blue' };
        if (value < THRESHOLDS.overhead.acceptable) return { level: 'acceptable', label: 'Moderate', color: 'yellow' };
        return { level: 'high', label: 'High', color: 'red' };
    }
    
    if (type === 'time') {
        if (value < THRESHOLDS.time.ultraFast) return { level: 'ultra-fast', label: 'Ultra Fast', color: 'purple' };
        if (value < THRESHOLDS.time.veryFast) return { level: 'very-fast', label: 'Very Fast', color: 'green' };
        if (value < THRESHOLDS.time.fast) return { level: 'fast', label: 'Fast', color: 'blue' };
        if (value < THRESHOLDS.time.acceptable) return { level: 'acceptable', label: 'Acceptable', color: 'yellow' };
        return { level: 'slow', label: 'Slow', color: 'orange' };
    }
    
    return { level: 'unknown', label: 'Unknown', color: 'gray' };
}

function createBadge(perfLevel) {
    const colors = {
        purple: 'bg-purple-100 text-purple-800',
        green: 'bg-green-100 text-green-800',
        blue: 'bg-blue-100 text-blue-800',
        yellow: 'bg-yellow-100 text-yellow-800',
        orange: 'bg-orange-100 text-orange-800',
        red: 'bg-red-100 text-red-800',
        gray: 'bg-gray-100 text-gray-800'
    };
    
    return `<span class="inline-block px-3 py-1 rounded-full text-xs font-semibold ${colors[perfLevel.color]}">${perfLevel.label}</span>`;
}

// ============================================================================
// Data Loading Functions
// ============================================================================

async function loadJSON(path) {
    try {
        const response = await fetch(path);
        if (!response.ok) return null;
        return await response.json();
    } catch (error) {
        console.warn(`Failed to load ${path}`);
        return null;
    }
}

async function scanDirectory(basePath, subPaths) {
    const results = {};
    for (const subPath of subPaths) {
        const data = await loadJSON(`${basePath}/${subPath}/base/estimates.json`);
        if (data) results[subPath] = data;
    }
    return results;
}

async function loadAllBenchmarks() {
    console.log('🔄 Loading all benchmark data...');
    
    const data = {};
    
    // AEAD benchmarks
    console.log('📊 Loading AEAD benchmarks...');
    const aeadOps = ['aes256_encrypt', 'aes256_decrypt', 'chacha20_encrypt', 'chacha20_decrypt'];
    const aeadSizes = ['64', '1024', '16384', '65536'];
    data.aead = {};
    for (const op of aeadOps) {
        data.aead[op] = await scanDirectory(`aead/${op}`, aeadSizes);
    }
    
    // Streaming benchmarks
    console.log('🌊 Loading streaming benchmarks...');
    const streamOps = ['aes256_stream_encrypt', 'aes256_stream_decrypt', 'chacha20_stream_encrypt'];
    const streamSizes = ['1mb', '10mb', '100mb'];
    data.stream = {};
    for (const op of streamOps) {
        data.stream[op] = await scanDirectory(`stream_encryption/${op}`, streamSizes);
    }
    
    // Key generation
    console.log('🔑 Loading key generation benchmarks...');
    data.keyGen = await scanDirectory('key_generation', ['aes256_generate_key', 'chacha20_generate_key']);
    
    // KDF benchmarks
    console.log('🔐 Loading KDF benchmarks...');
    data.kdf = await scanDirectory('kdf', ['argon2_interactive', 'argon2_low_memory', 'pbkdf2_sha256_600k', 'pbkdf2_sha256_10k', 'hkdf_sha256']);
    
    // Signing benchmarks
    console.log('✍️ Loading signing benchmarks...');
    data.signing = await scanDirectory('signing', ['ed25519_keygen', 'ed25519_sign', 'ed25519_verify']);
    
    // Key exchange
    console.log('🤝 Loading key exchange benchmarks...');
    data.keyExchange = await scanDirectory('key_exchange', ['x25519_keygen', 'x25519_dh', 'x25519_dh_derive']);
    
    // RSA (if available)
    data.rsa = await scanDirectory('rsa', ['rsa2048_keygen', 'rsa4096_keygen', 'rsa2048_encrypt', 'rsa2048_decrypt', 'rsa2048_sign', 'rsa2048_verify']);
    
    // Comparisons
    console.log('⚖️ Loading comparison benchmarks...');
    const compSizes = ['64', '1024', '16384', '65536'];
    data.comparison = {
        sha256: {
            crabgraph: await scanDirectory('comparison_sha256/crabgraph', compSizes),
            rustcrypto: await scanDirectory('comparison_sha256/rustcrypto', compSizes)
        },
        sha512: {
            crabgraph: await scanDirectory('comparison_sha512/crabgraph', compSizes),
            rustcrypto: await scanDirectory('comparison_sha512/rustcrypto', compSizes)
        },
        hmac_sha256: {
            crabgraph: await scanDirectory('comparison_hmac_sha256/crabgraph', compSizes),
            rustcrypto: await scanDirectory('comparison_hmac_sha256/rustcrypto', compSizes)
        },
        hmac_sha512: {
            crabgraph: await scanDirectory('comparison_hmac_sha512/crabgraph', compSizes),
            rustcrypto: await scanDirectory('comparison_hmac_sha512/rustcrypto', compSizes)
        }
    };
    
    console.log('✅ All benchmark data loaded!');
    return data;
}

// ============================================================================
// Statistical Analysis
// ============================================================================

function calculateStatistics(data) {
    const stats = {
        totalBenchmarks: 0,
        categories: {},
        performanceSummary: {
            excellent: 0,
            good: 0,
            acceptable: 0,
            slow: 0
        },
        topPerformers: [],
        needsImprovement: [],
        averageOverhead: 0,
        overheadSamples: 0
    };
    
    // Analyze AEAD
    let aeadPerf = [];
    for (const [op, sizes] of Object.entries(data.aead)) {
        for (const [size, bench] of Object.entries(sizes)) {
            if (bench && bench.mean) {
                stats.totalBenchmarks++;
                const bytes = parseInt(size);
                const throughput = calculateThroughput(bytes, bench.mean.point_estimate);
                const perf = getPerformanceLevel(throughput, 'throughput');
                aeadPerf.push({ op, size, throughput, perf });
                
                stats.performanceSummary[perf.level === 'hw-accel' ? 'excellent' : perf.level]++;
                
                if (throughput.mbps > 500) {
                    stats.topPerformers.push({ name: `${op}/${size}`, metric: formatThroughput(throughput), category: 'AEAD' });
                } else if (throughput.mbps < 50) {
                    stats.needsImprovement.push({ name: `${op}/${size}`, metric: formatThroughput(throughput), category: 'AEAD' });
                }
            }
        }
    }
    stats.categories.aead = aeadPerf;
    
    // Analyze comparisons for overhead
    for (const [hashType, impls] of Object.entries(data.comparison)) {
        if (impls.crabgraph && impls.rustcrypto) {
            for (const size of Object.keys(impls.crabgraph)) {
                const crab = impls.crabgraph[size];
                const rust = impls.rustcrypto[size];
                if (crab && rust && crab.mean && rust.mean) {
                    stats.totalBenchmarks += 2;
                    const overhead = ((crab.mean.point_estimate - rust.mean.point_estimate) / rust.mean.point_estimate) * 100;
                    stats.averageOverhead += overhead;
                    stats.overheadSamples++;
                }
            }
        }
    }
    
    if (stats.overheadSamples > 0) {
        stats.averageOverhead /= stats.overheadSamples;
    }
    
    // Analyze KDF
    let kdfCount = 0;
    for (const [name, bench] of Object.entries(data.kdf)) {
        if (bench && bench.mean) {
            stats.totalBenchmarks++;
            kdfCount++;
        }
    }
    stats.categories.kdf = kdfCount;
    
    // Analyze signing
    let signingCount = 0;
    for (const [name, bench] of Object.entries(data.signing)) {
        if (bench && bench.mean) {
            stats.totalBenchmarks++;
            signingCount++;
            const perf = getPerformanceLevel(bench.mean.point_estimate, 'time');
            if (bench.mean.point_estimate < 100000) { // < 100µs
                stats.topPerformers.push({ name, metric: formatTime(bench.mean.point_estimate), category: 'Signing' });
            }
        }
    }
    stats.categories.signing = signingCount;
    
    // Analyze streaming
    let streamCount = 0;
    for (const [op, sizes] of Object.entries(data.stream)) {
        for (const [size, bench] of Object.entries(sizes)) {
            if (bench && bench.mean) {
                stats.totalBenchmarks++;
                streamCount++;
            }
        }
    }
    stats.categories.stream = streamCount;
    
    // Sort top performers and needs improvement
    stats.topPerformers.sort((a, b) => {
        // Custom sorting logic
        return 0;
    }).slice(0, 5);
    
    stats.needsImprovement.sort().slice(0, 5);
    
    return stats;
}

function calculateOverallGrade(stats) {
    let score = 100;
    let details = [];
    
    // Check average overhead
    if (stats.averageOverhead < 10) {
        details.push({ icon: '✅', text: `Excellent wrapper efficiency (${stats.averageOverhead.toFixed(1)}% overhead)`, color: 'text-green-600' });
    } else if (stats.averageOverhead < 20) {
        score -= 5;
        details.push({ icon: '👍', text: `Good wrapper efficiency (${stats.averageOverhead.toFixed(1)}% overhead)`, color: 'text-blue-600' });
    } else {
        score -= 15;
        details.push({ icon: '⚠️', text: `Moderate wrapper overhead (${stats.averageOverhead.toFixed(1)}%)`, color: 'text-yellow-600' });
    }
    
    // Check performance distribution
    const totalPerf = stats.performanceSummary.excellent + stats.performanceSummary.good + stats.performanceSummary.acceptable + stats.performanceSummary.slow;
    const excellentRatio = stats.performanceSummary.excellent / totalPerf;
    
    if (excellentRatio > 0.7) {
        details.push({ icon: '🚀', text: `${(excellentRatio * 100).toFixed(0)}% of operations are excellent performance`, color: 'text-green-600' });
    } else if (excellentRatio > 0.5) {
        score -= 5;
        details.push({ icon: '👌', text: `${(excellentRatio * 100).toFixed(0)}% of operations are excellent performance`, color: 'text-blue-600' });
    } else {
        score -= 10;
        details.push({ icon: '📊', text: `${(excellentRatio * 100).toFixed(0)}% of operations are excellent performance`, color: 'text-yellow-600' });
    }
    
    // Check top performers
    if (stats.topPerformers.length > 0) {
        details.push({ icon: '⭐', text: `${stats.topPerformers.length} operations in top performance tier`, color: 'text-purple-600' });
    }
    
    // Check if there are slow operations
    if (stats.needsImprovement.length > 0) {
        score -= 5;
        details.push({ icon: '🔧', text: `${stats.needsImprovement.length} operations could be optimized`, color: 'text-orange-600' });
    }
    
    // Grade conversion
    let grade, color;
    if (score >= 95) { grade = 'A+'; color = 'text-purple-600'; }
    else if (score >= 90) { grade = 'A'; color = 'text-green-600'; }
    else if (score >= 85) { grade = 'A-'; color = 'text-green-600'; }
    else if (score >= 80) { grade = 'B+'; color = 'text-blue-600'; }
    else if (score >= 75) { grade = 'B'; color = 'text-blue-600'; }
    else { grade = 'C+'; color = 'text-yellow-600'; }
    
    return { grade, score, details, color };
}

// ============================================================================
// Rendering Functions
// ============================================================================

function renderOverallGrade(gradeInfo, stats) {
    document.getElementById('overall-grade').textContent = gradeInfo.grade;
    document.getElementById('overall-grade').className = `text-7xl font-bold mb-2 ${gradeInfo.color}`;
    
    const verdict = `
        <strong class="text-2xl">Score: ${gradeInfo.score}/100</strong><br>
        Based on ${stats.totalBenchmarks} benchmark measurements across ${Object.keys(stats.categories).length} categories.
        ${gradeInfo.score >= 90 ? 'Outstanding performance!' : gradeInfo.score >= 80 ? 'Excellent overall performance.' : 'Good performance with room for optimization.'}
    `;
    document.getElementById('overall-verdict').innerHTML = verdict;
    
    const detailsHTML = gradeInfo.details.map(d => `
        <div class="flex items-start space-x-2">
            <span class="text-2xl">${d.icon}</span>
            <span class="${d.color} font-medium">${d.text}</span>
        </div>
    `).join('');
    document.getElementById('grade-details').innerHTML = detailsHTML;
}

function renderKeyMetrics(data, stats) {
    const metrics = [];
    
    // Best AEAD throughput
    if (data.aead.aes256_encrypt && data.aead.aes256_encrypt['65536']) {
        const bench = data.aead.aes256_encrypt['65536'];
        const throughput = calculateThroughput(65536, bench.mean.point_estimate);
        metrics.push({
            icon: 'fa-bolt',
            color: 'from-yellow-400 to-orange-500',
            label: 'Peak AEAD Speed',
            value: formatThroughput(throughput),
            badge: createBadge(getPerformanceLevel(throughput, 'throughput'))
        });
    }
    
    // Average overhead
    if (stats.averageOverhead > 0) {
        const perf = getPerformanceLevel(stats.averageOverhead, 'overhead');
        metrics.push({
            icon: 'fa-layer-group',
            color: 'from-blue-400 to-indigo-500',
            label: 'Avg Wrapper Overhead',
            value: `${stats.averageOverhead.toFixed(1)}%`,
            badge: createBadge(perf)
        });
    }
    
    // Fastest signing
    if (data.signing.ed25519_sign) {
        const bench = data.signing.ed25519_sign;
        const perf = getPerformanceLevel(bench.mean.point_estimate, 'time');
        metrics.push({
            icon: 'fa-signature',
            color: 'from-green-400 to-emerald-500',
            label: 'Ed25519 Signing',
            value: formatTime(bench.mean.point_estimate),
            badge: createBadge(perf)
        });
    }
    
    // Total benchmarks
    metrics.push({
        icon: 'fa-chart-bar',
        color: 'from-purple-400 to-pink-500',
        label: 'Total Benchmarks',
        value: stats.totalBenchmarks.toString(),
        badge: '<span class="inline-block px-3 py-1 rounded-full text-xs font-semibold bg-gray-100 text-gray-800">Operations</span>'
    });
    
    const html = metrics.map(m => `
        <div class="bg-white rounded-xl shadow-lg p-6 transform hover:scale-105 transition-transform duration-200">
            <div class="flex items-center justify-between mb-3">
                <div class="bg-gradient-to-br ${m.color} w-12 h-12 rounded-lg flex items-center justify-center text-white">
                    <i class="fas ${m.icon} text-xl"></i>
                </div>
                ${m.badge}
            </div>
            <div class="text-3xl font-bold mb-1">${m.value}</div>
            <div class="text-gray-600 text-sm font-medium">${m.label}</div>
        </div>
    `).join('');
    
    document.getElementById('key-metrics-grid').innerHTML = html;
}

function renderAEADChart(data) {
    const ctx = document.getElementById('aeadChart');
    if (!ctx) return;
    
    const sizes = ['64', '1024', '16384', '65536'];
    const aesData = sizes.map(size => {
        const bench = data.aead.aes256_encrypt?.[size];
        if (!bench) return null;
        return calculateThroughput(parseInt(size), bench.mean.point_estimate).mbps;
    });
    
    const chachaData = sizes.map(size => {
        const bench = data.aead.chacha20_encrypt?.[size];
        if (!bench) return null;
        return calculateThroughput(parseInt(size), bench.mean.point_estimate).mbps;
    });
    
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['64 B', '1 KB', '16 KB', '64 KB'],
            datasets: [
                {
                    label: 'AES-256-GCM',
                    data: aesData,
                    backgroundColor: 'rgba(99, 102, 241, 0.7)',
                    borderColor: 'rgba(99, 102, 241, 1)',
                    borderWidth: 2
                },
                {
                    label: 'ChaCha20-Poly1305',
                    data: chachaData,
                    backgroundColor: 'rgba(251, 146, 60, 0.7)',
                    borderColor: 'rgba(251, 146, 60, 1)',
                    borderWidth: 2
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    title: { display: true, text: 'Throughput (MB/s)' }
                }
            },
            plugins: {
                legend: { position: 'top' },
                tooltip: {
                    callbacks: {
                        label: (context) => `${context.dataset.label}: ${context.parsed.y.toFixed(2)} MB/s`
                    }
                }
            }
        }
    });
}

function renderOverheadChart(data) {
    const ctx = document.getElementById('overheadChart');
    if (!ctx) return;
    
    const sizes = ['64', '1024', '16384', '65536'];
    const overheadData = {
        sha256: [],
        sha512: [],
        hmac256: [],
        hmac512: []
    };
    
    sizes.forEach(size => {
        // SHA-256
        const sha256Crab = data.comparison.sha256?.crabgraph?.[size];
        const sha256Rust = data.comparison.sha256?.rustcrypto?.[size];
        if (sha256Crab && sha256Rust) {
            overheadData.sha256.push(((sha256Crab.mean.point_estimate - sha256Rust.mean.point_estimate) / sha256Rust.mean.point_estimate) * 100);
        }
        
        // SHA-512
        const sha512Crab = data.comparison.sha512?.crabgraph?.[size];
        const sha512Rust = data.comparison.sha512?.rustcrypto?.[size];
        if (sha512Crab && sha512Rust) {
            overheadData.sha512.push(((sha512Crab.mean.point_estimate - sha512Rust.mean.point_estimate) / sha512Rust.mean.point_estimate) * 100);
        }
    });
    
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: ['64 B', '1 KB', '16 KB', '64 KB'],
            datasets: [
                {
                    label: 'SHA-256 Overhead',
                    data: overheadData.sha256,
                    borderColor: 'rgb(59, 130, 246)',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    tension: 0.4
                },
                {
                    label: 'SHA-512 Overhead',
                    data: overheadData.sha512,
                    borderColor: 'rgb(168, 85, 247)',
                    backgroundColor: 'rgba(168, 85, 247, 0.1)',
                    tension: 0.4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    title: { display: true, text: 'Overhead (%)' }
                }
            },
            plugins: {
                legend: { position: 'top' },
                tooltip: {
                    callbacks: {
                        label: (context) => `${context.dataset.label}: ${context.parsed.y.toFixed(1)}%`
                    }
                }
            }
        }
    });
}

function renderDistributionChart(stats) {
    const ctx = document.getElementById('distributionChart');
    if (!ctx) return;
    
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Excellent', 'Good', 'Acceptable', 'Slow'],
            datasets: [{
                data: [
                    stats.performanceSummary.excellent,
                    stats.performanceSummary.good,
                    stats.performanceSummary.acceptable,
                    stats.performanceSummary.slow
                ],
                backgroundColor: [
                    'rgba(34, 197, 94, 0.8)',
                    'rgba(59, 130, 246, 0.8)',
                    'rgba(251, 191, 36, 0.8)',
                    'rgba(239, 68, 68, 0.8)'
                ],
                borderWidth: 2,
                borderColor: '#fff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'bottom' },
                tooltip: {
                    callbacks: {
                        label: (context) => {
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((context.parsed / total) * 100).toFixed(1);
                            return `${context.label}: ${context.parsed} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

function renderSpeedCategories(stats) {
    const categories = [
        { name: 'Top Performers', items: stats.topPerformers, icon: 'fa-trophy', color: 'text-yellow-500' },
        { name: 'Needs Optimization', items: stats.needsImprovement, icon: 'fa-wrench', color: 'text-orange-500' }
    ];
    
    const html = categories.map(cat => `
        <div class="border-l-4 border-${cat.color.split('-')[1]}-500 pl-4">
            <h4 class="font-semibold ${cat.color} mb-2 flex items-center">
                <i class="fas ${cat.icon} mr-2"></i> ${cat.name}
            </h4>
            <ul class="space-y-1 text-sm">
                ${cat.items.slice(0, 3).map(item => `
                    <li class="flex justify-between">
                        <span class="text-gray-700">${item.name}</span>
                        <span class="font-mono text-gray-600">${item.metric}</span>
                    </li>
                `).join('') || '<li class="text-gray-500 italic">None</li>'}
            </ul>
        </div>
    `).join('');
    
    document.getElementById('speed-categories').innerHTML = html;
}

function renderTables(data) {
    // AEAD Table
    let aeadHTML = '<h4 class="text-lg font-semibold mb-3">AES-256-GCM vs ChaCha20-Poly1305</h4>';
    aeadHTML += '<div class="overflow-x-auto"><table class="w-full text-sm"><thead class="bg-gray-100"><tr>';
    aeadHTML += '<th class="px-4 py-3 text-left">Operation</th><th class="px-4 py-3 text-left">Size</th><th class="px-4 py-3 text-right">Mean Time</th><th class="px-4 py-3 text-right">Throughput</th><th class="px-4 py-3 text-center">Rating</th></tr></thead><tbody>';
    
    ['aes256_encrypt', 'chacha20_encrypt'].forEach(op => {
        const opName = op.includes('aes') ? 'AES-256-GCM' : 'ChaCha20-Poly1305';
        ['64', '1024', '16384', '65536'].forEach(size => {
            const bench = data.aead[op]?.[size];
            if (bench) {
                const sizeStr = size < 1024 ? `${size} B` : `${size / 1024} KB`;
                const throughput = calculateThroughput(parseInt(size), bench.mean.point_estimate);
                const perf = getPerformanceLevel(throughput, 'throughput');
                aeadHTML += `<tr class="border-t hover:bg-gray-50">
                    <td class="px-4 py-3">${opName}</td>
                    <td class="px-4 py-3">${sizeStr}</td>
                    <td class="px-4 py-3 text-right font-mono">${formatTime(bench.mean.point_estimate)}</td>
                    <td class="px-4 py-3 text-right font-mono font-semibold">${formatThroughput(throughput)}</td>
                    <td class="px-4 py-3 text-center">${createBadge(perf)}</td>
                </tr>`;
            }
        });
    });
    
    aeadHTML += '</tbody></table></div>';
    document.getElementById('tab-aead').innerHTML = aeadHTML;
    
    // Streaming Table
    let streamHTML = '<h4 class="text-lg font-semibold mb-3">Large File Encryption</h4>';
    streamHTML += '<div class="overflow-x-auto"><table class="w-full text-sm"><thead class="bg-gray-100"><tr>';
    streamHTML += '<th class="px-4 py-3 text-left">Cipher</th><th class="px-4 py-3 text-left">File Size</th><th class="px-4 py-3 text-right">Mean Time</th><th class="px-4 py-3 text-right">Throughput</th><th class="px-4 py-3 text-center">Rating</th></tr></thead><tbody>';
    
    ['aes256_stream_encrypt', 'chacha20_stream_encrypt'].forEach(op => {
        const opName = op.includes('aes') ? 'AES-256-GCM-STREAM' : 'ChaCha20-STREAM';
        ['1mb', '10mb', '100mb'].forEach(size => {
            const bench = data.stream[op]?.[size];
            if (bench) {
                const bytes = size === '1mb' ? 1048576 : size === '10mb' ? 10485760 : 104857600;
                const throughput = calculateThroughput(bytes, bench.mean.point_estimate);
                const perf = getPerformanceLevel(throughput, 'throughput');
                streamHTML += `<tr class="border-t hover:bg-gray-50">
                    <td class="px-4 py-3">${opName}</td>
                    <td class="px-4 py-3">${size.toUpperCase()}</td>
                    <td class="px-4 py-3 text-right font-mono">${formatTime(bench.mean.point_estimate)}</td>
                    <td class="px-4 py-3 text-right font-mono font-semibold">${formatThroughput(throughput)}</td>
                    <td class="px-4 py-3 text-center">${createBadge(perf)}</td>
                </tr>`;
            }
        });
    });
    
    streamHTML += '</tbody></table></div>';
    streamHTML += '<div class="mt-4 p-4 bg-yellow-50 border-l-4 border-yellow-400 text-sm">';
    streamHTML += '<p><strong class="text-yellow-800">Note:</strong> Streaming encryption prioritizes memory efficiency over raw speed. Lower throughput is expected and acceptable for large file handling.</p>';
    streamHTML += '</div>';
    document.getElementById('tab-stream').innerHTML = streamHTML;
    
    // KDF Table
    let kdfHTML = '<h4 class="text-lg font-semibold mb-3">Password Hashing & Key Derivation</h4>';
    kdfHTML += '<div class="overflow-x-auto"><table class="w-full text-sm"><thead class="bg-gray-100"><tr>';
    kdfHTML += '<th class="px-4 py-3 text-left">Function</th><th class="px-4 py-3 text-left">Parameters</th><th class="px-4 py-3 text-right">Mean Time</th><th class="px-4 py-3 text-center">Security</th></tr></thead><tbody>';
    
    const kdfEntries = [
        ['argon2_interactive', 'Argon2', 'Interactive (default)'],
        ['argon2_low_memory', 'Argon2', 'Low Memory'],
        ['pbkdf2_sha256_600k', 'PBKDF2-SHA256', '600,000 iterations'],
        ['pbkdf2_sha256_10k', 'PBKDF2-SHA256', '10,000 iterations'],
        ['hkdf_sha256', 'HKDF-SHA256', 'Fast KDF']
    ];
    
    kdfEntries.forEach(([key, name, params]) => {
        const bench = data.kdf[key];
        if (bench) {
            const security = key.includes('argon2') ? 'Very High' : key.includes('600k') ? 'High' : key.includes('10k') ? 'Medium' : 'N/A';
            const secColor = security === 'Very High' ? 'bg-green-100 text-green-800' : security === 'High' ? 'bg-blue-100 text-blue-800' : 'bg-yellow-100 text-yellow-800';
            kdfHTML += `<tr class="border-t hover:bg-gray-50">
                <td class="px-4 py-3 font-semibold">${name}</td>
                <td class="px-4 py-3">${params}</td>
                <td class="px-4 py-3 text-right font-mono">${formatTime(bench.mean.point_estimate)}</td>
                <td class="px-4 py-3 text-center"><span class="inline-block px-3 py-1 rounded-full text-xs font-semibold ${secColor}">${security}</span></td>
            </tr>`;
        }
    });
    
    kdfHTML += '</tbody></table></div>';
    kdfHTML += '<div class="mt-4 p-4 bg-blue-50 border-l-4 border-blue-400 text-sm">';
    kdfHTML += '<p><strong class="text-blue-800">Security Note:</strong> Slow KDF times are intentional! They protect against brute-force attacks. Argon2 and PBKDF2 are designed to be computationally expensive.</p>';
    kdfHTML += '</div>';
    document.getElementById('tab-kdf').innerHTML = kdfHTML;
    
    // Asymmetric Table
    let asymHTML = '<h4 class="text-lg font-semibold mb-3">Ed25519 & X25519</h4>';
    asymHTML += '<div class="overflow-x-auto"><table class="w-full text-sm"><thead class="bg-gray-100"><tr>';
    asymHTML += '<th class="px-4 py-3 text-left">Operation</th><th class="px-4 py-3 text-right">Mean Time</th><th class="px-4 py-3 text-center">Rating</th></tr></thead><tbody>';
    
    const asymOps = [
        ['ed25519_keygen', 'Ed25519 Key Generation'],
        ['ed25519_sign', 'Ed25519 Sign Message'],
        ['ed25519_verify', 'Ed25519 Verify Signature'],
        ['x25519_keygen', 'X25519 Key Generation'],
        ['x25519_dh', 'X25519 Diffie-Hellman'],
        ['x25519_dh_derive', 'X25519 DH + Derivation']
    ];
    
    asymOps.forEach(([key, name]) => {
        const bench = key.startsWith('ed') ? data.signing[key] : data.keyExchange[key];
        if (bench) {
            const perf = getPerformanceLevel(bench.mean.point_estimate, 'time');
            asymHTML += `<tr class="border-t hover:bg-gray-50">
                <td class="px-4 py-3">${name}</td>
                <td class="px-4 py-3 text-right font-mono">${formatTime(bench.mean.point_estimate)}</td>
                <td class="px-4 py-3 text-center">${createBadge(perf)}</td>
            </tr>`;
        }
    });
    
    asymHTML += '</tbody></table></div>';
    document.getElementById('tab-asymmetric').innerHTML = asymHTML;
    
    // Comparison Table
    let compHTML = '<h4 class="text-lg font-semibold mb-3">CrabGraph vs Raw RustCrypto</h4>';
    compHTML += '<div class="overflow-x-auto"><table class="w-full text-sm"><thead class="bg-gray-100"><tr>';
    compHTML += '<th class="px-4 py-3 text-left">Algorithm</th><th class="px-4 py-3 text-left">Size</th><th class="px-4 py-3 text-right">CrabGraph</th><th class="px-4 py-3 text-right">RustCrypto</th><th class="px-4 py-3 text-right">Overhead</th><th class="px-4 py-3 text-center">Rating</th></tr></thead><tbody>';
    
    ['sha256', 'sha512', 'hmac_sha256', 'hmac_sha512'].forEach(algo => {
        const algoName = algo.toUpperCase().replace('_', '-');
        ['64', '1024', '16384', '65536'].forEach(size => {
            const crab = data.comparison[algo]?.crabgraph?.[size];
            const rust = data.comparison[algo]?.rustcrypto?.[size];
            if (crab && rust) {
                const overhead = ((crab.mean.point_estimate - rust.mean.point_estimate) / rust.mean.point_estimate) * 100;
                const perf = getPerformanceLevel(overhead, 'overhead');
                const sizeStr = size < 1024 ? `${size} B` : `${size / 1024} KB`;
                compHTML += `<tr class="border-t hover:bg-gray-50">
                    <td class="px-4 py-3">${algoName}</td>
                    <td class="px-4 py-3">${sizeStr}</td>
                    <td class="px-4 py-3 text-right font-mono">${formatTime(crab.mean.point_estimate)}</td>
                    <td class="px-4 py-3 text-right font-mono">${formatTime(rust.mean.point_estimate)}</td>
                    <td class="px-4 py-3 text-right font-mono font-semibold">+${overhead.toFixed(1)}%</td>
                    <td class="px-4 py-3 text-center">${createBadge(perf)}</td>
                </tr>`;
            }
        });
    });
    
    compHTML += '</tbody></table></div>';
    compHTML += '<div class="mt-4 p-4 bg-green-50 border-l-4 border-green-400 text-sm">';
    compHTML += '<p><strong class="text-green-800">Why Overhead Matters:</strong> CrabGraph provides type safety, automatic zeroization, and ergonomic APIs. Low overhead means these benefits come with minimal performance cost!</p>';
    compHTML += '</div>';
    document.getElementById('tab-comparison').innerHTML = compHTML;
}

function renderAllBenchmarks() {
    const categories = [
        { path: 'aead/report/index.html', name: 'AEAD Encryption', icon: 'fa-lock', color: 'from-blue-500 to-indigo-600' },
        { path: 'stream_encryption/report/index.html', name: 'Streaming Encryption', icon: 'fa-stream', color: 'from-purple-500 to-pink-600' },
        { path: 'kdf/report/index.html', name: 'Key Derivation', icon: 'fa-key', color: 'from-green-500 to-emerald-600' },
        { path: 'signing/report/index.html', name: 'Digital Signatures', icon: 'fa-signature', color: 'from-yellow-500 to-orange-600' },
        { path: 'key_exchange/report/index.html', name: 'Key Exchange', icon: 'fa-exchange-alt', color: 'from-red-500 to-rose-600' },
        { path: 'comparison_sha256/report/index.html', name: 'SHA-256 Comparison', icon: 'fa-chart-line', color: 'from-cyan-500 to-blue-600' },
        { path: 'comparison_sha512/report/index.html', name: 'SHA-512 Comparison', icon: 'fa-chart-area', color: 'from-indigo-500 to-purple-600' },
        { path: 'stream_chunk_size/report/index.html', name: 'Chunk Size Analysis', icon: 'fa-cubes', color: 'from-teal-500 to-green-600' },
        { path: 'stream_vs_memory/report/index.html', name: 'Stream vs Memory', icon: 'fa-memory', color: 'from-orange-500 to-red-600' }
    ];
    
    const html = categories.map(cat => `
        <a href="${cat.path}" target="_blank" class="block bg-white rounded-lg shadow hover:shadow-xl transition-all duration-200 overflow-hidden transform hover:-translate-y-1">
            <div class="bg-gradient-to-br ${cat.color} p-4 text-white">
                <i class="fas ${cat.icon} text-2xl"></i>
            </div>
            <div class="p-4">
                <h4 class="font-semibold text-gray-800">${cat.name}</h4>
                <p class="text-xs text-gray-600 mt-1">View detailed report →</p>
            </div>
        </a>
    `).join('');
    
    document.getElementById('all-benchmarks').innerHTML = html;
}

// ============================================================================
// Tab Switching
// ============================================================================

function switchTab(tabName) {
    // Update button states
    document.querySelectorAll('button[onclick^="switchTab"]').forEach(btn => {
        btn.classList.remove('border-primary', 'text-primary', 'border-b-2');
        btn.classList.add('text-gray-600');
    });
    event.target.classList.add('border-primary', 'text-primary', 'border-b-2');
    event.target.classList.remove('text-gray-600');
    
    // Update content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.add('hidden');
    });
    document.getElementById(`tab-${tabName}`).classList.remove('hidden');
}

// ============================================================================
// Main Initialization
// ============================================================================

async function init() {
    try {
        console.log('🚀 Initializing CrabGraph Benchmark Dashboard...');
        
        // Load all data
        const data = await loadAllBenchmarks();
        allBenchmarkData.raw = data;
        
        // Calculate statistics
        console.log('📊 Calculating statistics...');
        const stats = calculateStatistics(data);
        allBenchmarkData.statistics = stats;
        
        // Calculate grade
        const gradeInfo = calculateOverallGrade(stats);
        
        // Hide loading, show content
        document.getElementById('loading').classList.add('hidden');
        document.getElementById('main-content').classList.remove('hidden');
        
        // Render all components
        console.log('🎨 Rendering dashboard...');
        document.getElementById('total-benchmarks').textContent = `${stats.totalBenchmarks} benchmarks analyzed`;
        
        renderOverallGrade(gradeInfo, stats);
        renderKeyMetrics(data, stats);
        renderAEADChart(data);
        renderOverheadChart(data);
        renderDistributionChart(stats);
        renderSpeedCategories(stats);
        renderTables(data);
        renderAllBenchmarks();
        
        console.log('✅ Dashboard ready!');
        
    } catch (error) {
        console.error('❌ Error initializing dashboard:', error);
        document.getElementById('loading').innerHTML = `
            <div class="text-center">
                <i class="fas fa-exclamation-triangle text-6xl text-red-500 mb-4"></i>
                <h2 class="text-2xl font-bold text-white mb-2">Error Loading Benchmarks</h2>
                <p class="text-white opacity-80">${error.message}</p>
                <p class="text-white text-sm opacity-60 mt-4">Check console for details</p>
            </div>
        `;
    }
}

// Start when page loads
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}
