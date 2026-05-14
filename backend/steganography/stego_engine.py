import io
from PIL import Image


class SteganographyEngine:
    """A production-grade engine for LSB Image Steganography.

    Note:
        LSB steganography is fragile against image compression and resizing.
        This implementation natively enforces PNG byte-streams to guarantee
        data integrity across the API layer.
    """

    EOF_MARKER = "####EOF####"

    @classmethod
    def _text_to_binary(cls, text: str) -> str:
        """Convert UTF-8 text into a continuous string of 8-bit binary characters.

        Args:
            text: The plaintext string to convert.

        Returns:
            A string of bits representing the input text.
        """
        return "".join(format(ord(c), "08b") for c in text)

    @classmethod
    def _binary_to_text(cls, binary_data: str) -> str:
        """Chunk binary string into 8-bit segments and convert to characters.

        Args:
            binary_data: A string of bits.

        Returns:
            The decoded UTF-8 plaintext string.
        """
        chars = [
            chr(int(binary_data[i : i + 8], 2)) for i in range(0, len(binary_data), 8)
        ]
        return "".join(chars)

    @classmethod
    def encode(cls, image_bytes: bytes, secret_text: str) -> bytes:
        """Encode secret text into an image using LSB substitution.

        Args:
            image_bytes: Raw bytes of the source image.
            secret_text: The plaintext to hide.

        Returns:
            Raw bytes of the encoded PNG image.

        Raises:
            ValueError: If the secret text exceeds the image's pixel capacity.
        """
        img = Image.open(io.BytesIO(image_bytes))
        if img.mode != "RGB":
            img = img.convert("RGB")

        binary_payload = cls._text_to_binary(secret_text + cls.EOF_MARKER)
        width, height = img.size
        total_pixels = width * height
        # Each pixel has 3 color channels (R, G, B)
        if len(binary_payload) > total_pixels * 3:
            raise ValueError("Payload size exceeds image capacity.")

        pixels = list(img.getdata())
        new_pixels = []
        bit_index = 0
        payload_len = len(binary_payload)

        for pixel in pixels:
            new_pixel = list(pixel)
            for i in range(3):  # R, G, B channels
                if bit_index < payload_len:
                    bit = binary_payload[bit_index]
                    # Replace LSB: pixel_val & ~1 | int(bit)
                    new_pixel[i] = new_pixel[i] & ~1 | int(bit)
                    bit_index += 1
            new_pixels.append(tuple(new_pixel))

        img.putdata(new_pixels)
        output_buffer = io.BytesIO()
        img.save(output_buffer, format="PNG")
        return output_buffer.getvalue()

    @classmethod
    def decode(cls, image_bytes: bytes) -> str:
        """Extract hidden text from an image using LSB decoding.

        Args:
            image_bytes: Raw bytes of the encoded PNG image.

        Returns:
            The extracted secret text.

        Raises:
            ValueError: If the EOF marker is not found in the image bits.
        """
        img = Image.open(io.BytesIO(image_bytes))
        if img.mode != "RGB":
            img = img.convert("RGB")

        pixels = list(img.getdata())
        extracted_bits = []
        for pixel in pixels:
            for channel in pixel:
                extracted_bits.append(str(channel & 1))

        full_binary = "".join(extracted_bits)
        binary_eof = cls._text_to_binary(cls.EOF_MARKER)

        # Search the string in 8-bit chunks for the binary equivalent of EOF_MARKER
        for i in range(0, len(full_binary), 8):
            chunk = full_binary[i : i + 8]
            if not chunk or len(chunk) < 8:
                break

            # Optimization: check for EOF_MARKER by looking ahead from current byte
            if full_binary[i : i + len(binary_eof)] == binary_eof:
                secret_binary = full_binary[:i]
                return cls._binary_to_text(secret_binary)

        raise ValueError("No hidden data detected (EOF marker missing).")
