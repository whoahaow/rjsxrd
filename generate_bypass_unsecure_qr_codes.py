import os
import qrcode
from urllib.parse import quote

def generate_bypass_unsecure_qr_codes():
    # Create the qr-codes/bypass-unsecure directory if it doesn't exist
    output_dir = "qr-codes/bypass-unsecure"
    os.makedirs(output_dir, exist_ok=True)
    
    # Base URL for the bypass-unsecure configs
    base_url = "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/"
    
    # Generate QR code for bypass-unsecure-all.txt
    all_url = base_url + "bypass-unsecure-all.txt"
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(all_url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(os.path.join(output_dir, "bypass-unsecure-all.png"))
    print(f"Generated QR code for {all_url}")
    
    # Generate QR codes for bypass-unsecure-1.txt through bypass-unsecure-5.txt
    for i in range(1, 6):
        filename = f"bypass-unsecure-{i}.txt"
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
        img.save(os.path.join(output_dir, f"bypass-unsecure-{i}.png"))
        print(f"Generated QR code for {file_url}")

if __name__ == "__main__":
    generate_bypass_unsecure_qr_codes()