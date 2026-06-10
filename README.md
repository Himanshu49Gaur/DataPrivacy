# Data Privacy & Forensics Toolkit (DPFT)
### *Advanced Spatial UI Environment for Cryptographic Engineering*

---

## 1. Introduction
The **Data Privacy & Forensics Toolkit (DPFT)** is a high-performance, full-stack ecosystem engineered for rigorous cryptographic operations, digital forensics, and secure media processing. Designed to bridge the gap between complex mathematical primitives and market-standard user experience, the suite provides a localized, zero-trust sandbox where sensitive data is processed entirely in-memory. By utilizing a stateless FastAPI backend and a hardware-accelerated Spatial UI, DPFT offers a definitive environment for developers, security researchers, and forensic analysts to execute high-fidelity privacy protocols without the risks associated with cloud-based processing.

The platform features an extensive library of **29+ mathematical cryptographic primitives**, spanning Classical ciphers, Symmetric block/stream ciphers, and Asymmetric public-key systems. Beyond raw encryption, the toolkit integrates a production-grade **Least Significant Bit (LSB) Steganography** engine and a **zero-disk I/O Document Watermarking** system for both images and PDFs. Every operation is optimized for high-throughput API environments, leveraging raw byte-streams to eliminate disk I/O bottlenecks and ensure absolute data volatility.

## 2. Problem Statement
The modern digital landscape is plagued by systemic vulnerabilities that threaten data sovereignty and forensic integrity:
*   **Cloud Dependency & Surveillance:** Most commercial cryptographic tools rely on remote APIs, exposing sensitive keys and plaintext to third-party harvesting and metadata analysis.
*   **Black-Box Cryptography:** Closed-source implementations often contain backdoors or non-standard padding schemes that compromise long-term security.
*   **Disk-Leakage in Forensics:** Standard media processing tools often create temporary cache files on local disks, leaving forensic "ghosts" that can be recovered by adversaries even after the primary data is deleted.
*   **Monolithic Inefficiency:** Traditional security suites are often bloated and difficult to integrate into modern web-based microservice architectures.

## 3. Objectives
The DPFT was engineered to achieve the following technical benchmarks:
*   **Zero-Trust Execution Environment:** Establish a localized processing paradigm where data never leaves the user's controlled environment, ensuring 100% sovereignty.
*   **Mathematical Rigor & RFC Compliance:** Enforce absolute adherence to cryptographic standards, including **RFC 8439 (ChaCha20)**, **NIST FIPS 197 (AES)**, and **secp256k1** elliptic curves for verifiable security.
*   **High-Scalability Dynamic Routing:** Utilize advanced Python introspection and dynamic module loading to handle 20+ algorithms through a single, lean API gateway without endpoint bloat.
*   **Spatial UX for Complex Analysis:** Deliver a high-fidelity **Spatial UI (Glassmorphism)** that utilizes 3D hardware acceleration to provide an intuitive, professional interface for complex forensic tasks.

## 4. Proposed Solution
The DPFT implements a **Stateless Hybrid Architecture** that decouples heavy mathematical processing from the user interface. The backend is powered by **FastAPI**, serving as a high-speed ASGI gateway that manipulates data as in-memory byte-streams (`io.BytesIO`). This prevents the creation of temporary files, ensuring that all forensic operations are volatile and secure.

The frontend is a bespoke **Vanilla ES6+ JavaScript** application that bypasses the overhead of heavy frameworks. It utilizes **CSS 3D transforms** and **Glassmorphism design principles** to create a "Spatial UI" where tools are treated as floating modules on a hardware-accelerated stage. Communication between layers is handled via a unified RESTful API, utilizing Base64 serialization for binary data transport.

## 5. Methodology
The engineering approach for DPFT prioritizes security, performance, and maintainability through the following patterns:

> **Dynamic API Orchestration:** To avoid a monolithic routing file for 29+ algorithms, the backend utilizes an `importlib` registry pattern. Incoming URL paths are dynamically mapped to cryptographic modules, allowing the system to scale to hundreds of algorithms with zero code changes to the core `app.py`.

> **Low-Level Mathematical Boundaries:** Stream ciphers such as **ChaCha20** and **Salsa20** are implemented with strict enforcement of 32-bit word boundaries using Python's `struct` module. This ensures that bitwise rotations and additions mirror the hardware-level ARX (Addition-Rotation-XOR) operations intended by the original designers.

> **Forensic Integrity:** The Steganography and Watermarking engines utilize **Least Significant Bit (LSB) substitution**. The steganography engine natively enforces **PNG byte-streams** to prevent lossy compression (like JPEG) from destroying hidden bit-data. The PDF watermarking engine leverages **ReportLab** to generate dynamic stamps that are merged into the source PDF's content stream at the byte level.

> **Side-Channel Mitigation:** Key Derivation Functions (KDF) utilize **scrypt** and **PBKDF2-HMAC-SHA256**. The backend enforces constant-time string comparisons (`hmac.compare_digest`) to mitigate timing side-channel attacks during authentication and key verification.

## 6. Project Structure
```text
.
├── backend/
│   ├── app.py                      # FastAPI core gateway & dynamic router
│   ├── algorithms/                 # Cryptographic primitive library
│   │   ├── aes_cipher.py           # NIST Standard AES-256 GCM/CBC
│   │   ├── chacha20_cipher.py      # RFC 8439 Stream Cipher
│   │   ├── rsa_cipher.py           # Asymmetric Public-Key System
│   │   ├── ecc_cipher.py           # Elliptic Curve Cryptography
│   │   ├── blowfish_cipher.py      # Feistel Network Block Cipher
│   │   ├── ...                     # 25+ additional modules
│   │   └── factory.py              # Centralized Cipher Registry
│   ├── steganography/
│   │   └── stego_engine.py         # LSB Bit-Substitution Engine
│   └── watermarking/
│       └── watermark_engine.py     # In-memory PDF/Image overlay system
├── frontend/
│   ├── index.html                  # Spatial UI Framework (Glassmorphism)
│   ├── css/
│   │   └── style.css               # 3D Transforms & Glassmorphism styles
│   └── js/
│       ├── ui.js                   # Spatial DOM & 3D Stage management
│       └── api.js                  # Async Fetch & Typewriter rendering
├── tests/                          # Comprehensive validation suite
│   ├── test_stego_engine.py
│   ├── test_watermark_engine.py
│   └── ...
└── README.md                       # Technical Documentation
```

## 7. Technology Used
| Category | Technology | Architectural Role |
| :--- | :--- | :--- |
| **Backend Framework** | Python 3.10+ / FastAPI | High-speed ASGI routing & async processing. |
| **Cryptography** | PyCryptodome / Hashlib | Mathematical primitives & low-level bit manipulation. |
| **Media Processing** | Pillow / PyPDF / ReportLab | Image LSB substitution & PDF content merging. |
| **Frontend Styling** | Tailwind CSS / Lucide | Utility-first styling & professional iconography. |
| **UI Interaction** | Vanilla ES6+ / DOM API | Dynamic form injection & 3D hardware acceleration. |
| **Data Transport** | REST / JSON / Base64 | Unified serialization for binary & text data. |

## 8. Key Features
*   **3D Spatial Dark Mode UI:** An immersive "Cyber Security" aesthetic utilizing frosted glassmorphism, background radial gradients, and real-time DOM injection to swap between 29+ toolsets seamlessly.
*   **Extensive Cryptographic Library:** A massive suite covering classical ciphers (Monoalphabetic, Polyalphabetic, Transposition), modern symmetric blocks (AES, Blowfish, DES), and advanced asymmetric systems (RSA, ECC, ElGamal).
*   **Memory-Hard KDF Authentication:** Implementation of the **scrypt** KDF, utilizing configurable CPU/RAM cost parameters to provide high resistance against GPU-based brute-force attacks.
*   **Forensic Media Processing:** Lossless PNG steganography and transparent PDF/Image watermarking executed entirely in RAM, leaving zero forensic trace on the host file system.

## 9. How to Use

### Prerequisites
*   Python 3.10 or higher
*   Modern Web Browser (Chrome/Firefox/Edge) for 3D CSS support

### Installation & Deployment
1. **Clone the Repository:**
   ```bash
   git clone https://github.com/your-username/data-privacy-toolkit.git
   cd data-privacy-toolkit
   ```

2. **Initialize Virtual Environment & Dependencies:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Launch the FastAPI Backend:**
   ```bash
   # From the root directory
   uvicorn backend.app:app --reload --port 8000
   ```

4. **Access the Frontend:**
   - Simply open `frontend/index.html` in your web browser.
   - The UI will automatically connect to the local backend at `http://localhost:8000`.

## 10. Results / Conclusion
The **Data Privacy & Forensics Toolkit** stands as a production-ready demonstration of secure, full-stack software engineering. By successfully bridging the gap between raw mathematical complexity and highly polished user experience, the project provides a scalable framework for privacy-preserving applications. The deployment of this toolkit proves that cryptographic rigor does not have to come at the cost of usability, offering a definitive sandbox for digital forensic analysis and secure data engineering.

## 11. About the Author
**Himanshu Gaur** is a high-impact Computer Science Engineering student specializing in **Cyber Security and Digital Forensics** at **VIT Bhopal University** (Expected Graduation: May 2027). A dedicated security researcher, Himanshu maintains a **top 1% global ranking on TryHackMe**, demonstrating elite-level proficiency in penetration testing and forensic analysis. His professional background includes a tenure as a **Cyber Security Intern at the Rajasthan Police Headquarters**, where he executed complex OSINT investigations and blockchain analysis to support law enforcement. The DPFT's architecture is a testament to his capability to engineer secure, scalable, and AI-integrated software solutions for the modern security landscape.
