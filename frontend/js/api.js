/**
 * api.js - Core API communication layer for DPFT.
 * Encapsulates all network requests to the FastAPI backend.
 */

const API_BASE = 'http://localhost:8000/api';

window.api = {
    /**
     * Handle Cryptographic requests (Encrypt/Decrypt).
     * @param {string} action - 'encrypt' or 'decrypt'.
     * @param {string} algorithm - The protocol name.
     * @param {Object} payload - Data containing text, key, nonce, and position.
     */
    async handleCipherRequest(action, algorithm, payload) {
        try {
            const response = await fetch(`${API_BASE}/crypto/${action}/${algorithm}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            });

            const data = await response.json();

            if (response.ok) {
                window.ui.displayResult(action, data.result);
            } else {
                this.showToast(data.detail || "PROTOCOL_EXECUTION_FAILURE", "error");
            }
        } catch (error) {
            this.showToast("BACKEND_COMMUNICATION_ERROR: CONNECTION_REFUSED", "error");
        }
    },

    /**
     * Handle Media Forensic requests (Stego/Watermarking).
     * @param {string} endpoint - The API endpoint.
     * @param {FormData} formData - Multipart data containing files and payloads.
     */
    async handleMediaRequest(endpoint, formData) {
        try {
            const response = await fetch(`${API_BASE}/${endpoint}`, {
                method: 'POST',
                body: formData
            });

            if (response.ok) {
                if (endpoint === 'stego/decode') {
                    const data = await response.json();
                    this.showToast("DECODING_COMPLETE", "success");
                    // Display decrypted payload in a safe modal or alert
                    alert(`DECRYPTED_PAYLOAD: ${data.secret_text}`);
                } else {
                    const blob = await response.blob();
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `forensic_output_${Date.now()}.bin`;
                    document.body.appendChild(a);
                    a.click();
                    a.remove();
                    this.showToast("FORENSIC_ASSET_GENERATED", "success");
                }
            } else {
                const data = await response.json();
                this.showToast(data.detail || "MEDIA_PROCESS_FAILED", "error");
            }
        } catch (error) {
            this.showToast("BACKEND_COMMUNICATION_ERROR", "error");
        }
    },

    /**
     * Global Toast Notification System.
     * @param {string} message - The text to display.
     * @param {string} type - 'error' or 'success'.
     */
    showToast(message, type = 'error') {
        const layer = document.getElementById('toast-layer');
        if (!layer) return;

        const toast = document.createElement('div');
        const borderColor = type === 'error' ? 'border-red-500/50' : 'border-emerald-500/50';
        const textColor = type === 'error' ? 'text-red-400' : 'text-emerald-400';
        
        toast.className = `toast-in glass-panel p-4 rounded-xl border ${borderColor} ${textColor} bg-black/80 backdrop-blur-xl flex items-center space-x-3 w-72 shadow-2xl`;
        if (type === 'error') toast.classList.add('shake');

        toast.innerHTML = `
            <div class="flex-1">
                <p class="text-[10px] font-bold uppercase tracking-widest">${type}</p>
                <p class="text-xs font-medium opacity-80">${message}</p>
            </div>
        `;

        layer.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(20px)';
            setTimeout(() => toast.remove(), 300);
        }, 5000);
    }
};
