from PIL import Image
import base64
from io import BytesIO

def convert_image_to_webp_base64(image_path, output_size=(800, 800), quality=90):
    # Open the image file
    with Image.open(image_path) as img:
        # Resize the image
        img = img.resize(output_size, Image.LANCZOS)

        # Convert to WebP and save to a BytesIO stream
        buffer = BytesIO()
        img.save(buffer, format="WEBP", quality=quality)
        buffer.seek(0)

        # Encode to base64
        img_base64 = base64.b64encode(buffer.read()).decode("utf-8")

        # Create the web image URL format
        web_image_url = f"data:image/webp;base64,{img_base64}"
        
        return web_image_url

# Use the function
image_path = "image.png"  # Path to your image file
webp_base64_url = convert_image_to_webp_base64(image_path, (40, 40))
print(webp_base64_url)
