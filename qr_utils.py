import qrcode
from PIL import Image

def generate_qr(data: str, filename: str = None) -> Image.Image:
    """Generate a QR code image from data. Optionally save to filename."""
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    if filename:
        img.save(filename)
    return img

def scan_qr(filename: str) -> str:
    """Scan a QR code from an image file and return the data."""
    try:
        from pyzbar.pyzbar import decode
        img = Image.open(filename)
        decoded = decode(img)
        if decoded:
            return decoded[0].data.decode()
        else:
            return "No QR code found."
    except ImportError:
        return "pyzbar not installed. Run: pip install pyzbar"
    except Exception as e:
        return f"Error: {e}" 