import os
import qrcode
from urllib.parse import quote

def generate_default_qr_codes():
    # Create the qr-codes/default directory if it doesn't exist
    output_dir = "qr-codes/default"
    os.makedirs(output_dir, exist_ok=True)

    # Base URL for the default configs
    base_url = "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/"

    # Get all .txt files from the githubmirror/default directory
    default_dir = "githubmirror/default"
    txt_files = [f for f in os.listdir(default_dir) if f.endswith('.txt')]

    # Generate QR codes for all .txt files
    for filename in txt_files:
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

        # Create safe filename by replacing . with - and keeping the .png extension
        safe_filename = filename.replace(".", "-") + ".png"
        img.save(os.path.join(output_dir, safe_filename))
        print(f"Generated QR code for {file_url}")

if __name__ == "__main__":
    generate_default_qr_codes()