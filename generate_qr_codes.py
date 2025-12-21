import os
import qrcode
from urllib.parse import quote

def generate_qr_codes():
    # Create the qr-codes/bypass directory if it doesn't exist
    output_dir = "qr-codes/bypass"
    os.makedirs(output_dir, exist_ok=True)
    
    # Base URL for the bypass configs
    base_url = "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/"
    
    # Generate QR code for bypass-all.txt
    all_url = base_url + "bypass-all.txt"
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(all_url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(os.path.join(output_dir, "bypass-all.png"))
    print(f"Generated QR code for {all_url}")
    
    # Generate QR codes for bypass-1.txt through bypass-5.txt
    for i in range(1, 6):
        filename = f"bypass-{i}.txt"
        file_url = base_url + filename
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(file_url)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(os.path.join(output_dir, f"bypass-{i}.png"))
        print(f"Generated QR code for {file_url}")

if __name__ == "__main__":
    generate_qr_codes()