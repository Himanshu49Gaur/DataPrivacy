/**
 * ui.js - Frontend orchestration and DOM manipulation for DPFT.
 * Preserves Spatial UI features while wiring functional modules.
 */

const toolContainer = document.getElementById('active-tool-container');
const cipherTemplate = document.getElementById('template-cipher');
const mediaTemplate = document.getElementById('template-media');
const algoSearch = document.getElementById('algo-search');
const stage = document.getElementById('stage');
const statusTicker = document.getElementById('status-ticker');

let currentAlgorithm = null;

window.ui = {
    /**
     * Renders the processed result to the UI with a typewriter effect.
     * @param {string} action - 'encrypt' or 'decrypt'.
     * @param {string} result - The output string from the API.
     */
    displayResult(action, result) {
        const outputField = document.getElementById('output-data');
        if (!outputField) return;

        outputField.value = '';
        let i = 0;
        const speed = result.length > 300 ? 1 : 10;

        function type() {
            if (i < result.length) {
                const chunk = result.slice(i, i + 5);
                outputField.value += chunk;
                i += 5;
                setTimeout(type, speed);
            }
        }
        type();
    }
};

/**
 * Sidebar Search Logic
 */
algoSearch.addEventListener('input', (e) => {
    const query = e.target.value.toLowerCase();
    document.querySelectorAll('.algo-link').forEach(link => {
        const text = link.innerText.toLowerCase();
        link.parentElement.style.display = text.includes(query) ? 'block' : 'none';
    });
});

/**
 * Navigation & Template Loading
 */
document.querySelectorAll('.algo-link').forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        document.querySelectorAll('.algo-link').forEach(l => l.classList.remove('active'));
        link.classList.add('active');
        
        currentAlgorithm = link.dataset.algo;
        const name = link.innerText;
        loadTool(currentAlgorithm, name);
    });
});

function loadTool(algo, name) {
    toolContainer.innerHTML = '';
    const isMedia = algo.includes('/') || algo.startsWith('watermark');
    const template = isMedia ? mediaTemplate : cipherTemplate;

    const clone = template.content.cloneNode(true);
    toolContainer.appendChild(clone);

    if (isMedia) {
        initMediaUI(algo, name);
    } else {
        initCipherUI(algo, name);
    }

    statusTicker.innerText = `PROTOCOL_INITIALIZED: ${algo.toUpperCase()}`;
    apply3DTilt();
}

/**
 * Cipher Module Logic & Event Binding
 */
function initCipherUI(algo, name) {
    document.getElementById('tool-name').innerText = name;
    
    const btnEncrypt = document.getElementById('btn-mode-encrypt');
    const btnDecrypt = document.getElementById('btn-mode-decrypt');
    const inputField = document.getElementById('input-data');
    const keyField = document.getElementById('param-key');
    const nonceField = document.getElementById('param-nonce');
    const posField = document.getElementById('param-pos');

    const handleAction = async (action, btn) => {
        if (!inputField.value) {
            window.api.showToast("INPUT_STREAM_NULL", "error");
            return;
        }
        if (!keyField.value) {
            window.api.showToast("MASTER_KEY_MISSING", "error");
            return;
        }

        // Loading State
        const originalText = btn.innerText;
        btn.disabled = true;
        btn.innerText = "PROCESSING...";

        const payload = {
            text: inputField.value,
            key: keyField.value,
            nonce: nonceField.value || null,
            position: parseInt(posField.value) || 0
        };

        await window.api.handleCipherRequest(action, algo, payload);

        // Restore State
        btn.disabled = false;
        btn.innerText = originalText;
    };

    btnEncrypt.onclick = () => handleAction('encrypt', btnEncrypt);
    btnDecrypt.onclick = () => handleAction('decrypt', btnDecrypt);

    document.getElementById('btn-copy').onclick = () => {
        const out = document.getElementById('output-data');
        navigator.clipboard.writeText(out.value);
        window.api.showToast("BUFFER_COPIED_TO_CLIPBOARD", "success");
    };
}

/**
 * Media Module Logic & Event Binding
 */
function initMediaUI(endpoint, name) {
    document.getElementById('media-tool-name').innerText = name;
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('media-input');
    const nameDisplay = document.getElementById('file-name-display');
    const payloadGroup = document.getElementById('media-payload-group');
    const btnExec = document.getElementById('btn-media-exec');

    if (endpoint === 'stego/decode') payloadGroup.style.display = 'none';

    dropzone.onclick = () => fileInput.click();
    fileInput.onchange = () => {
        if (fileInput.files.length > 0) {
            nameDisplay.innerText = fileInput.files[0].name;
            nameDisplay.classList.add('text-emerald-400');
        }
    };

    // Drag & Drop
    ['dragover', 'dragenter'].forEach(ev => {
        dropzone.addEventListener(ev, (e) => {
            e.preventDefault();
            dropzone.classList.add('border-emerald-500');
        });
    });

    ['dragleave', 'drop'].forEach(ev => {
        dropzone.addEventListener(ev, (e) => {
            e.preventDefault();
            dropzone.classList.remove('border-emerald-500');
            if (ev === 'drop' && e.dataTransfer.files.length > 0) {
                fileInput.files = e.dataTransfer.files;
                nameDisplay.innerText = fileInput.files[0].name;
            }
        });
    });

    btnExec.onclick = async () => {
        if (fileInput.files.length === 0) {
            window.api.showToast("DATA_SOURCE_MISSING", "error");
            return;
        }

        const originalText = btnExec.innerText;
        btnExec.disabled = true;
        btnExec.innerText = "EXECUTING_PROTOCOL...";

        const formData = new FormData();
        formData.append('file', fileInput.files[0]);
        if (endpoint !== 'stego/decode') {
            const field = endpoint.startsWith('watermark') ? 'text' : 'secret_text';
            formData.append(field, document.getElementById('media-payload').value);
        }

        await window.api.handleMediaRequest(endpoint, formData);

        btnExec.disabled = false;
        btnExec.innerText = originalText;
    };
}

/**
 * Spatial Effect Logic
 */
function apply3DTilt() {
    const card = document.querySelector('.tilt-effect');
    if (!card) return;

    stage.onmousemove = (e) => {
        const rect = card.getBoundingClientRect();
        const centerX = rect.left + rect.width / 2;
        const centerY = rect.top + rect.height / 2;
        const mouseX = e.clientX - centerX;
        const mouseY = e.clientY - centerY;
        
        const rotateX = (mouseY / (window.innerHeight / 2)) * -5;
        const rotateY = (mouseX / (window.innerWidth / 2)) * 5;
        card.style.transform = `rotateX(${rotateX}deg) rotateY(${rotateY}deg)`;
    };

    stage.onmouseleave = () => {
        card.style.transform = `rotateX(0deg) rotateY(0deg)`;
    };
}
