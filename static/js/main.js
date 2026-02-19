/**
 * Phishing URL Detector - Main JavaScript
 * ========================================
 * Handles URL analysis and result display
 */

// ==================== TAB NAVIGATION ====================

/**
 * Switch between single URL and batch analysis tabs
 * @param {string} tab - 'single' or 'batch'
 */
function showTab(tab) {
    // Update nav links
    document.getElementById('singleTab').classList.toggle('active', tab === 'single');
    document.getElementById('batchTab').classList.toggle('active', tab === 'batch');
    
    // Show/hide sections
    document.getElementById('singleSection').classList.toggle('d-none', tab !== 'single');
    document.getElementById('batchSection').classList.toggle('d-none', tab !== 'batch');
    
    // Hide results
    hideResults();
}

// ==================== SINGLE URL ANALYSIS ====================

/**
 * Analyze a single URL
 * @param {Event} event - Form submit event
 */
async function analyzeSingle(event) {
    event.preventDefault();
    
    const urlInput = document.getElementById('urlInput');
    const url = urlInput.value.trim();
    
    if (!url) {
        showError('Please enter a URL to analyze');
        return;
    }
    
    // Show loading
    showLoading(true);
    hideResults();
    
    try {
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url })
        });
        
        const data = await response.json();
        
        if (data.success) {
            displaySingleResult(data.result);
        } else {
            showError(data.error || 'An error occurred during analysis');
        }
    } catch (error) {
        showError('Failed to connect to server. Please try again.');
        console.error('Analysis error:', error);
    } finally {
        showLoading(false);
    }
}

/**
 * Display single URL analysis result
 * @param {Object} result - Analysis result object
 */
function displaySingleResult(result) {
    const container = document.getElementById('singleResult');
    const resultsSection = document.getElementById('resultsSection');
    
    // Get risk level styling
    const riskStyle = getRiskStyle(result.risk_level);
    
    // Build result HTML
    let html = `
        <div class="card result-card shadow">
            <div class="card-header ${riskStyle.headerClass}">
                <h5 class="mb-0">
                    <i class="${riskStyle.icon}"></i> Analysis Result
                </h5>
            </div>
            <div class="card-body">
                <!-- URL Display -->
                <div class="mb-3">
                    <strong>Analyzed URL:</strong>
                    <div class="text-muted word-break-all small">${escapeHtml(result.url)}</div>
                </div>
                
                <!-- Risk Score -->
                <div class="row mb-4">
                    <div class="col-md-6">
                        <div class="text-center p-3 bg-light rounded">
                            <div class="risk-badge ${riskStyle.badgeClass} mb-2">
                                ${result.risk_level.toUpperCase()}
                            </div>
                            <div class="display-4 fw-bold">${result.risk_score}</div>
                            <div class="text-muted">Risk Score / 100</div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="p-3">
                            <h6><i class="bi bi-bar-chart"></i> Risk Level</h6>
                            <div class="score-bar-container">
                                <div class="score-bar ${result.risk_level}" 
                                     style="width: ${result.risk_score}%"></div>
                            </div>
                            <p class="mt-3 mb-0 small text-muted">
                                ${result.analysis_summary}
                            </p>
                        </div>
                    </div>
                </div>
                
                <!-- Warnings -->
                ${result.warnings.length > 0 ? `
                    <div class="mb-4">
                        <h6><i class="bi bi-exclamation-triangle text-warning"></i> Warnings (${result.warnings.length})</h6>
                        ${result.warnings.map(w => `
                            <div class="warning-card ${w.severity}">
                                <div class="d-flex justify-content-between align-items-start">
                                    <div>
                                        <span class="severity-badge bg-${getSeverityClass(w.severity)} text-white me-2">
                                            ${w.severity}
                                        </span>
                                        <strong>${w.message}</strong>
                                    </div>
                                </div>
                                <p class="mb-0 mt-2 small text-muted">
                                    <i class="bi bi-info-circle"></i> ${w.explanation}
                                </p>
                            </div>
                        `).join('')}
                    </div>
                ` : ''}
                
                <!-- Recommendations -->
                <div class="mb-4">
                    <h6><i class="bi bi-lightbulb text-info"></i> Recommendations</h6>
                    ${result.recommendations.map(r => `
                        <div class="alert alert-${getPriorityClass(r.priority)} py-2 mb-2">
                            <strong>${r.action}</strong>
                            <p class="mb-0 small">${r.details}</p>
                        </div>
                    `).join('')}
                </div>
                
                <!-- Features Accordion -->
                <div class="accordion" id="featuresAccordion">
                    <div class="accordion-item">
                        <h2 class="accordion-header">
                            <button class="accordion-button collapsed" type="button" 
                                    data-bs-toggle="collapse" data-bs-target="#featuresCollapse">
                                <i class="bi bi-list-check me-2"></i> View Technical Details
                            </button>
                        </h2>
                        <div id="featuresCollapse" class="accordion-collapse collapse" 
                             data-bs-parent="#featuresAccordion">
                            <div class="accordion-body">
                                <table class="table table-sm feature-table">
                                    <tbody>
                                        ${Object.entries(result.features).map(([key, value]) => `
                                            <tr>
                                                <td><code>${formatFeatureName(key)}</code></td>
                                                <td class="feature-value ${value}">
                                                    ${formatFeatureValue(value)}
                                                </td>
                                            </tr>
                                        `).join('')}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    container.innerHTML = html;
    container.classList.remove('d-none');
    resultsSection.classList.remove('d-none');
    
    // Scroll to results
    container.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ==================== BATCH ANALYSIS ====================

/**
 * Analyze multiple URLs
 * @param {Event} event - Form submit event
 */
async function analyzeBatch(event) {
    event.preventDefault();
    
    const batchInput = document.getElementById('batchInput');
    const urlsText = batchInput.value.trim();
    
    if (!urlsText) {
        showError('Please enter URLs to analyze');
        return;
    }
    
    // Parse URLs (one per line)
    const urls = urlsText.split('\n')
        .map(url => url.trim())
        .filter(url => url.length > 0);
    
    if (urls.length === 0) {
        showError('No valid URLs found');
        return;
    }
    
    // Show loading
    showLoading(true);
    hideResults();
    
    try {
        const response = await fetch('/batch', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ urls: urls })
        });
        
        const data = await response.json();
        
        if (data.success) {
            displayBatchResults(data.results);
        } else {
            showError(data.error || 'An error occurred during batch analysis');
        }
    } catch (error) {
        showError('Failed to connect to server. Please try again.');
        console.error('Batch analysis error:', error);
    } finally {
        showLoading(false);
    }
}

/**
 * Display batch analysis results
 * @param {Array} results - Array of analysis results
 */
function displayBatchResults(results) {
    const container = document.getElementById('batchResult');
    const resultsSection = document.getElementById('resultsSection');
    
    // Count by risk level
    const counts = {
        safe: results.filter(r => r.risk_level === 'safe').length,
        suspicious: results.filter(r => r.risk_level === 'suspicious').length,
        phishing: results.filter(r => r.risk_level === 'phishing').length
    };
    
    let html = `
        <div class="card result-card shadow">
            <div class="card-header bg-info text-white">
                <h5 class="mb-0">
                    <i class="bi bi-list-ul"></i> Batch Analysis Results
                </h5>
            </div>
            <div class="card-body">
                <!-- Summary -->
                <div class="row mb-4">
                    <div class="col-4 text-center">
                        <div class="p-3 rounded bg-success bg-opacity-10">
                            <div class="h3 mb-0 text-success">${counts.safe}</div>
                            <small class="text-muted">Safe</small>
                        </div>
                    </div>
                    <div class="col-4 text-center">
                        <div class="p-3 rounded bg-warning bg-opacity-10">
                            <div class="h3 mb-0 text-warning">${counts.suspicious}</div>
                            <small class="text-muted">Suspicious</small>
                        </div>
                    </div>
                    <div class="col-4 text-center">
                        <div class="p-3 rounded bg-danger bg-opacity-10">
                            <div class="h3 mb-0 text-danger">${counts.phishing}</div>
                            <small class="text-muted">Phishing</small>
                        </div>
                    </div>
                </div>
                
                <!-- Results List -->
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead>
                            <tr>
                                <th>URL</th>
                                <th class="text-center">Risk Level</th>
                                <th class="text-center">Score</th>
                                <th class="text-center">Warnings</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${results.map(result => {
                                const style = getRiskStyle(result.risk_level);
                                return `
                                    <tr class="cursor-pointer" onclick="showBatchDetail(${JSON.stringify(result).replace(/"/g, '&quot;')})">
                                        <td class="word-break-all">
                                            <small>${escapeHtml(result.url.substring(0, 50))}${result.url.length > 50 ? '...' : ''}</small>
                                        </td>
                                        <td class="text-center">
                                            <span class="badge ${style.badgeClass}">${result.risk_level}</span>
                                        </td>
                                        <td class="text-center">
                                            <span class="fw-bold">${result.risk_score}</span>
                                        </td>
                                        <td class="text-center">
                                            <span class="badge bg-secondary">${result.warnings.length}</span>
                                        </td>
                                    </tr>
                                `;
                            }).join('')}
                        </tbody>
                    </table>
                </div>
                
                <!-- Detail View Area -->
                <div id="batchDetailView" class="mt-3 d-none">
                    <!-- Will be populated when clicking a row -->
                </div>
            </div>
        </div>
    `;
    
    container.innerHTML = html;
    container.classList.remove('d-none');
    resultsSection.classList.remove('d-none');
    
    // Scroll to results
    container.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/**
 * Show detailed view for a batch result
 * @param {Object} result - Analysis result
 */
function showBatchDetail(result) {
    const container = document.getElementById('batchDetailView');
    const style = getRiskStyle(result.risk_level);
    
    container.innerHTML = `
        <div class="alert ${style.alertClass}">
            <h6><i class="${style.icon}"></i> ${result.url}</h6>
            <p class="mb-2"><strong>Risk Score:</strong> ${result.risk_score}/100</p>
            <p class="mb-0"><strong>Summary:</strong> ${result.analysis_summary}</p>
            ${result.warnings.length > 0 ? `
                <hr>
                <strong>Warnings:</strong>
                <ul class="mb-0 mt-2">
                    ${result.warnings.map(w => `<li>${w.message}</li>`).join('')}
                </ul>
            ` : ''}
        </div>
    `;
    container.classList.remove('d-none');
}

// ==================== HELPER FUNCTIONS ====================

/**
 * Get styling based on risk level
 * @param {string} level - Risk level (safe/suspicious/phishing)
 * @returns {Object} Style object
 */
function getRiskStyle(level) {
    const styles = {
        safe: {
            headerClass: 'bg-success text-white',
            badgeClass: 'risk-safe',
            icon: 'bi-check-circle-fill',
            alertClass: 'alert-success'
        },
        suspicious: {
            headerClass: 'bg-warning',
            badgeClass: 'risk-suspicious',
            icon: 'bi-exclamation-triangle-fill',
            alertClass: 'alert-warning'
        },
        phishing: {
            headerClass: 'bg-danger text-white',
            badgeClass: 'risk-phishing',
            icon: 'bi-x-circle-fill',
            alertClass: 'alert-danger'
        }
    };
    return styles[level] || styles.safe;
}

/**
 * Get Bootstrap class for severity
 * @param {string} severity - Severity level
 * @returns {string} Bootstrap class
 */
function getSeverityClass(severity) {
    const classes = {
        high: 'danger',
        medium: 'warning',
        low: 'info'
    };
    return classes[severity] || 'secondary';
}

/**
 * Get Bootstrap class for priority
 * @param {string} priority - Priority level
 * @returns {string} Bootstrap class
 */
function getPriorityClass(priority) {
    const classes = {
        critical: 'danger',
        high: 'warning',
        medium: 'info',
        low: 'light',
        info: 'light'
    };
    return classes[priority] || 'light';
}

/**
 * Format feature name for display
 * @param {string} name - Feature name
 * @returns {string} Formatted name
 */
function formatFeatureName(name) {
    return name.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

/**
 * Format feature value for display
 * @param {*} value - Feature value
 * @returns {string} Formatted value
 */
function formatFeatureValue(value) {
    if (typeof value === 'boolean') {
        return value ? '✓ Yes' : '✗ No';
    }
    return value;
}

/**
 * Escape HTML special characters
 * @param {string} text - Text to escape
 * @returns {string} Escaped text
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Show/hide loading spinner
 * @param {boolean} show - Whether to show loading
 */
function showLoading(show) {
    const spinner = document.getElementById('loadingSpinner');
    spinner.classList.toggle('d-none', !show);
    
    // Disable buttons during loading
    document.getElementById('analyzeBtn').disabled = show;
    document.getElementById('batchBtn').disabled = show;
}

/**
 * Hide all result sections
 */
function hideResults() {
    document.getElementById('singleResult').classList.add('d-none');
    document.getElementById('batchResult').classList.add('d-none');
    document.getElementById('resultsSection').classList.add('d-none');
}

/**
 * Show error message
 * @param {string} message - Error message
 */
function showError(message) {
    const container = document.getElementById('singleResult');
    const resultsSection = document.getElementById('resultsSection');
    
    container.innerHTML = `
        <div class="alert alert-danger">
            <i class="bi bi-exclamation-circle"></i>
            <strong>Error:</strong> ${escapeHtml(message)}
        </div>
    `;
    
    container.classList.remove('d-none');
    resultsSection.classList.remove('d-none');
}

// ==================== INITIALIZATION ====================

document.addEventListener('DOMContentLoaded', function() {
    // Focus on URL input
    document.getElementById('urlInput').focus();
    
    // Add keyboard shortcut (Enter to analyze)
    document.getElementById('urlInput').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            analyzeSingle(e);
        }
    });
});
