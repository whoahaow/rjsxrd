import os
import qrcode

def generate_split_by_protocols_qr_codes():
    # Create the qr-codes/split-by-protocols directory if it doesn't exist
    output_dir = "qr-codes/split-by-protocols"
    os.makedirs(output_dir, exist_ok=True)
    
    # Base URL for the split-by-protocols configs
    base_url = "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/"
    
    # Get all .txt files from the githubmirror/split-by-protocols directory
    protocols_dir = "githubmirror/split-by-protocols"
    txt_files = [f for f in os.listdir(protocols_dir) if f.endswith('.txt')]
    
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
    generate_split_by_protocols_qr_codes()