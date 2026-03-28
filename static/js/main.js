// VenomStrike Main JavaScript
// For authorized security testing only.

'use strict';

// Utility functions
const VS = {
    // DOM helper
    $(selector) { return document.querySelector(selector); },
    $$(selector) { return document.querySelectorAll(selector); },
    
    // Toggle finding details
    toggleFinding(id) {
        const body = document.getElementById('body-' + id);
        const toggle = document.getElementById('toggle-' + id);
        if (!body) return;
        if (body.style.display === 'none' || !body.style.display) {
            body.style.display = 'block';
            if (toggle) toggle.textContent = '▲';
        } else {
            body.style.display = 'none';
            if (toggle) toggle.textContent = '▼';
        }
    },
    
    // Copy to clipboard
    copyToClipboard(text) {
        if (navigator.clipboard) {
            navigator.clipboard.writeText(text).then(() => {
                VS.showToast('Copied to clipboard!', 'success');
            });
        } else {
            const el = document.createElement('textarea');
            el.value = text;
            document.body.appendChild(el);
            el.select();
            document.execCommand('copy');
            document.body.removeChild(el);
            VS.showToast('Copied!', 'success');
        }
    },
    
    // Toast notifications
    showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;
        toast.style.cssText = `
            position: fixed; top: 20px; right: 20px; z-index: 9999;
            background: ${type === 'success' ? '#00ff41' : type === 'error' ? '#ff0040' : '#0099ff'};
            color: #000; padding: 10px 20px; border-radius: 4px;
            font-family: 'Courier New', monospace; font-size: 0.9rem;
            animation: slideIn 0.3s ease;
        `;
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 3000);
    },
    
    // Format timestamp
    formatTime(ts) {
        return new Date(ts * 1000).toLocaleString();
    },
    
    // Severity color mapping
    severityColor(severity) {
        const colors = {
            'Critical': '#ff0040',
            'High': '#ff6600',
            'Medium': '#ffcc00',
            'Low': '#0099ff',
            'Info': '#888888'
        };
        return colors[severity] || '#888888';
    },
    
    // Real-time scan polling
    pollScan(scanId, callback) {
        const interval = setInterval(async () => {
            try {
                const resp = await fetch(`/api/scan/${scanId}/status`);
                const data = await resp.json();
                callback(data);
                if (data.status === 'completed' || data.status === 'failed') {
                    clearInterval(interval);
                }
            } catch (e) {
                console.warn('Poll error:', e);
            }
        }, 2000);
        return interval;
    },
    
    // Initialize scan form
    initScanForm() {
        const form = VS.$('#scanForm');
        if (!form) return;
        
        form.addEventListener('submit', function(e) {
            const authorized = VS.$('#authorized');
            if (!authorized || !authorized.checked) {
                e.preventDefault();
                VS.showToast('You must confirm authorization before scanning.', 'error');
                return;
            }
            
            const btn = VS.$('#scanBtn');
            if (btn) {
                btn.innerHTML = '<span class="spinner">⏳</span> Scanning...';
                btn.disabled = true;
            }
        });
        
        // Target URL validation
        const targetInput = VS.$('#target');
        if (targetInput) {
            targetInput.addEventListener('blur', function() {
                const val = this.value.trim();
                if (val && !val.match(/^https?:\/\/.+/)) {
                    this.value = 'http://' + val;
                }
            });
        }
    },
    
    // Keyboard shortcuts
    initShortcuts() {
        document.addEventListener('keydown', function(e) {
            // Ctrl+Shift+C: copy scan results
            if (e.ctrlKey && e.shiftKey && e.key === 'C') {
                const results = document.querySelectorAll('.finding-card');
                if (results.length) {
                    const text = Array.from(results).map(r => r.textContent.trim()).join('\n---\n');
                    VS.copyToClipboard(text);
                }
            }
        });
    },
    
    // Initialize expandable code blocks
    initCodeBlocks() {
        VS.$$('.code-block').forEach(block => {
            if (block.scrollHeight > 200) {
                block.style.maxHeight = '200px';
                block.style.overflow = 'hidden';
                
                const toggle = document.createElement('button');
                toggle.textContent = 'Show more';
                toggle.className = 'btn btn-small code-toggle';
                toggle.style.marginTop = '5px';
                toggle.onclick = function() {
                    if (block.style.maxHeight === '200px') {
                        block.style.maxHeight = 'none';
                        toggle.textContent = 'Show less';
                    } else {
                        block.style.maxHeight = '200px';
                        toggle.textContent = 'Show more';
                    }
                };
                block.parentNode.insertBefore(toggle, block.nextSibling);
            }
        });
    },
    
    // Filter findings by severity
    initFindingFilter() {
        const filterBtns = VS.$$('[data-filter]');
        filterBtns.forEach(btn => {
            btn.addEventListener('click', function() {
                const severity = this.dataset.filter;
                VS.$$('.finding-card').forEach(card => {
                    if (severity === 'all' || card.classList.contains('severity-' + severity.toLowerCase())) {
                        card.style.display = '';
                    } else {
                        card.style.display = 'none';
                    }
                });
                filterBtns.forEach(b => b.classList.remove('active'));
                this.classList.add('active');
            });
        });
    },
    
    // Init all
    init() {
        this.initScanForm();
        this.initShortcuts();
        document.addEventListener('DOMContentLoaded', () => {
            this.initCodeBlocks();
            this.initFindingFilter();
        });
    }
};

VS.init();

// Make toggleFinding global for inline onclick
window.toggleFinding = VS.toggleFinding.bind(VS);

// Add CSS animation
const style = document.createElement('style');
style.textContent = `
@keyframes slideIn {
    from { transform: translateX(100px); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
}
`;
document.head.appendChild(style);
