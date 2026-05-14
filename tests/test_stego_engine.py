import io
from PIL import Image
from backend.steganography.stego_engine import SteganographyEngine

def test_steganography():
    # 1. Create a small test image (10x10 RGB)
    img = Image.new('RGB', (10, 10), color='red')
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='PNG')
    image_bytes = img_byte_arr.getvalue()

    secret_text = "Hello, World!"
    print(f"Original Secret: {secret_text}")

    # 2. Encode
    try:
        encoded_bytes = SteganographyEngine.encode(image_bytes, secret_text)
        print("Encoding successful.")
    except Exception as e:
        print(f"Encoding failed: {e}")
        return

    # 3. Decode
    try:
        decoded_text = SteganographyEngine.decode(encoded_bytes)
        print(f"Decoded Secret: {decoded_text}")
        
        if secret_text == decoded_text:
            print("SUCCESS: Decoded text matches original!")
        else:
            print("FAILURE: Decoded text does not match!")
    except Exception as e:
        print(f"Decoding failed: {e}")

if __name__ == "__main__":
    test_steganography()
