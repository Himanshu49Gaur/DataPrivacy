import io
from PIL import Image, ImageDraw, ImageFont
from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4


class WatermarkEngine:
    """A production-grade engine for document and image watermarking.

    This engine provides visible, non-destructive watermarking for asset
    provenance, optimized exclusively for in-memory byte streams suitable
    for high-throughput API environments.
    """

    @classmethod
    def watermark_image(cls, image_bytes: bytes, text: str, opacity: int = 128) -> bytes:
        """Apply a diagonal text watermark to an image.

        Args:
            image_bytes: Raw bytes of the source image.
            text: The watermark text.
            opacity: Opacity level from 0 (transparent) to 255 (opaque).

        Returns:
            Raw bytes of the watermarked PNG image.
        """
        base = Image.open(io.BytesIO(image_bytes)).convert("RGBA")
        width, height = base.size

        # Create a transparent overlay
        txt_overlay = Image.new("RGBA", base.size, (255, 255, 255, 0))
        draw = ImageDraw.Draw(txt_overlay)

        # Load default font
        font = ImageFont.load_default()
        
        # Calculate text position (center)
        # Note: load_default is small; in production, a TTF font would be scaled.
        # We use textbbox to center the fixed-size default font.
        bbox = draw.textbbox((0, 0), text, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        
        x = (width - text_width) // 2
        y = (height - text_height) // 2

        # Draw text with specified opacity
        draw.text((x, y), text, font=font, fill=(255, 255, 255, opacity))

        # Rotate overlay by 45 degrees
        txt_overlay = txt_overlay.rotate(45, resample=Image.BICUBIC, center=(width // 2, height // 2))

        # Composite and convert back to RGB
        combined = Image.alpha_composite(base, txt_overlay)
        final_image = combined.convert("RGB")

        output_buffer = io.BytesIO()
        final_image.save(output_buffer, format="PNG")
        return output_buffer.getvalue()

    @classmethod
    def watermark_pdf(cls, pdf_bytes: bytes, text: str, opacity: float = 0.5) -> bytes:
        """Apply a diagonal text watermark to every page of a PDF.

        Args:
            pdf_bytes: Raw bytes of the source PDF.
            text: The watermark text.
            opacity: Opacity level from 0.0 to 1.0.

        Returns:
            Raw bytes of the watermarked PDF.
        """
        # 1. Create watermark stamp
        packet = io.BytesIO()
        can = canvas.Canvas(packet, pagesize=A4)
        
        # Configure canvas
        can.setFont("Helvetica", 60)
        can.setFillGray(0.5, alpha=opacity)
        
        # Translate and rotate for diagonal placement
        # Center of standard A4 is approx (297.5, 421)
        can.translate(300, 450)
        can.rotate(45)
        can.drawCentredString(0, 0, text)
        can.save()
        
        packet.seek(0)
        watermark_pdf = PdfReader(packet)
        watermark_page = watermark_pdf.pages[0]

        # 2. Merge watermark into input PDF
        reader = PdfReader(io.BytesIO(pdf_bytes))
        writer = PdfWriter()

        for page in reader.pages:
            page.merge_page(watermark_page)
            writer.add_page(page)

        output_buffer = io.BytesIO()
        writer.write(output_buffer)
        return output_buffer.getvalue()
