import io
from PIL import Image
from reportlab.pdfgen import canvas
from backend.watermarking.watermark_engine import WatermarkEngine

def test_watermarking():
    print("Starting WatermarkEngine validation...")

    # 1. Test Image Watermarking
    img = Image.new('RGB', (500, 500), color='blue')
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='PNG')
    image_bytes = img_byte_arr.getvalue()

    try:
        watermarked_img_bytes = WatermarkEngine.watermark_image(image_bytes, "CONFIDENTIAL", opacity=100)
        print(f"Image watermarking successful. Output size: {len(watermarked_img_bytes)} bytes")
    except Exception as e:
        print(f"Image watermarking failed: {e}")

    # 2. Test PDF Watermarking
    pdf_packet = io.BytesIO()
    can = canvas.Canvas(pdf_packet)
    can.drawString(100, 750, "Original PDF Content")
    can.showPage()
    can.save()
    pdf_bytes = pdf_packet.getvalue()

    try:
        watermarked_pdf_bytes = WatermarkEngine.watermark_pdf(pdf_bytes, "DRAFT", opacity=0.3)
        print(f"PDF watermarking successful. Output size: {len(watermarked_pdf_bytes)} bytes")
    except Exception as e:
        print(f"PDF watermarking failed: {e}")

if __name__ == "__main__":
    test_watermarking()
