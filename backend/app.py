import importlib
import inspect
import io
from typing import Optional, Any
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from backend.steganography.stego_engine import SteganographyEngine
from backend.watermarking.watermark_engine import WatermarkEngine

app = FastAPI(title="Data Privacy Toolkit API", version="1.0.0")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class CipherRequest(BaseModel):
    """Flexible model for cryptographic requests."""

    text: str
    key: str
    position: int = 0
    nonce: Optional[str] = None


class CipherResponse(BaseModel):
    """Standard response model for cryptographic results."""

    result: str


@app.post("/api/crypto/{action}/{algorithm}", response_model=CipherResponse)
async def dynamic_crypto_handler(action: str, algorithm: str, request: CipherRequest):
    """Dynamically routes cryptographic requests to the appropriate module.

    This API utilizes dynamic module loading to efficiently route traffic across
    20+ cryptographic primitives while safely handling binary media streams in-memory.

    Args:
        action: Either 'encrypt' or 'decrypt'.
        algorithm: The algorithm name (e.g., 'aes', 'chacha20', 'rsa').
        request: The CipherRequest containing text, key, and optional params.

    Returns:
        CipherResponse containing the result string.

    Raises:
        HTTPException: 404 if algorithm not found, 400 for invalid action or method.
    """
    if action not in ["encrypt", "decrypt"]:
        raise HTTPException(status_code=400, detail="Action must be 'encrypt' or 'decrypt'.")

    module_path = f"backend.algorithms.{algorithm}_cipher"
    try:
        module = importlib.import_module(module_path)

        # Find the class ending with 'Cipher' in the module
        cipher_class = None
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if name.endswith("Cipher") and obj.__module__ == module_path:
                cipher_class = obj
                break

        if not cipher_class:
            raise AttributeError("Cipher class not found in module.")

        instance = cipher_class()
        method = getattr(instance, action)

        # Inspect signature to map request parameters
        sig = inspect.signature(method)
        kwargs = {}

        for param_name, param in sig.parameters.items():
            if param_name in ["text", "plaintext", "data", "message", "ciphertext"]:
                kwargs[param_name] = request.text
            elif "key" in param_name:
                # Handle conversion to bytes if hinted
                if param.annotation == bytes:
                    kwargs[param_name] = request.key.encode("utf-8")
                else:
                    kwargs[param_name] = request.key
            elif param_name == "nonce":
                if request.nonce is not None:
                    if param.annotation == bytes:
                        kwargs[param_name] = request.nonce.encode("utf-8")
                    else:
                        kwargs[param_name] = request.nonce
            elif param_name == "position":
                kwargs[param_name] = request.position

        result = method(**kwargs)
        return CipherResponse(result=str(result))

    except ImportError:
        raise HTTPException(status_code=404, detail=f"Algorithm '{algorithm}' not found.")
    except (AttributeError, KeyError):
        raise HTTPException(
            status_code=400, detail=f"Method '{action}' not supported for {algorithm}."
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Operation failed: {str(e)}")


@app.post("/api/stego/encode")
async def stego_encode(file: UploadFile = File(...), secret_text: str = Form(...)):
    """Encodes secret text into an image using LSB steganography.

    Args:
        file: The image file to hide text in.
        secret_text: The text to be hidden.

    Returns:
        Response containing the encoded PNG image bytes.
    """
    try:
        image_bytes = await file.read()
        output_bytes = SteganographyEngine.encode(image_bytes, secret_text)
        return Response(content=output_bytes, media_type="image/png")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/stego/decode")
async def stego_decode(file: UploadFile = File(...)):
    """Decodes secret text from an image.

    Args:
        file: The image file containing hidden text.

    Returns:
        JSON response with the extracted secret text.
    """
    try:
        image_bytes = await file.read()
        text = SteganographyEngine.decode(image_bytes)
        return {"secret_text": text}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/watermark/image")
async def watermark_image(file: UploadFile = File(...), text: str = Form(...)):
    """Applies a diagonal text watermark to an image.

    Args:
        file: The image file to watermark.
        text: The watermark text.

    Returns:
        Response containing the watermarked PNG image bytes.
    """
    try:
        image_bytes = await file.read()
        output_bytes = WatermarkEngine.watermark_image(image_bytes, text)
        return Response(content=output_bytes, media_type="image/png")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/watermark/pdf")
async def watermark_pdf(file: UploadFile = File(...), text: str = Form(...)):
    """Applies a diagonal text watermark to a PDF document.

    Args:
        file: The PDF file to watermark.
        text: The watermark text.

    Returns:
        Response containing the watermarked PDF bytes.
    """
    try:
        pdf_bytes = await file.read()
        output_bytes = WatermarkEngine.watermark_pdf(pdf_bytes, text)
        return Response(content=output_bytes, media_type="application/pdf")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
