#!/usr/bin/env python3
"""
Create PNG bitmap icons for RaspyJack menu on Raspberry Pi
Run this script on your Raspberry Pi to generate the icon files
"""
import os
import sys
from PIL import Image, ImageDraw

def create_icon_png(name, png_path, size=(16, 16)):
    """Create a simple PNG icon"""
    try:
        # Create a new image with transparent background
        img = Image.new('RGBA', size, (255, 255, 255, 0))
        draw = ImageDraw.Draw(img)
        
        # Simple icon representations using basic shapes
        if name == "scan_nmap":
            # Draw a magnifying glass (search icon)
            draw.ellipse([3, 3, 11, 11], outline=(0, 0, 0), width=2)
            draw.line([10, 10, 14, 14], fill=(0, 0, 0), width=2)
        elif name == "reverse_shell":
            # Draw a terminal-like rectangle
            draw.rectangle([2, 3, 14, 13], outline=(0, 0, 0), width=1, fill=(0, 0, 0))
            draw.text((4, 5), ">", fill=(0, 255, 0))
        elif name == "responder":
            # Draw a lightning bolt
            draw.polygon([(5, 2), (8, 2), (6, 8), (10, 8), (8, 14), (5, 14), (7, 8), (3, 8)], 
                        fill=(255, 255, 0), outline=(0, 0, 0))
        elif name == "mitm_sniff":
            # Draw network nodes with connections
            draw.ellipse([2, 2, 6, 6], fill=(255, 0, 0))
            draw.ellipse([10, 2, 14, 6], fill=(255, 0, 0))
            draw.ellipse([6, 10, 10, 14], fill=(255, 0, 0))
            draw.line([4, 4, 8, 8], fill=(0, 0, 0), width=1)
            draw.line([12, 4, 8, 8], fill=(0, 0, 0), width=1)
        elif name == "dns_spoofing":
            # Draw a server rack
            draw.rectangle([4, 2, 12, 14], outline=(0, 0, 0), width=1)
            draw.rectangle([5, 4, 11, 6], fill=(0, 255, 0))
            draw.rectangle([5, 8, 11, 10], fill=(255, 255, 0))
            draw.rectangle([5, 11, 11, 13], fill=(255, 0, 0))
        elif name == "network_info":
            # Draw wifi signal symbol
            draw.arc([2, 6, 14, 10], 0, 180, fill=(0, 0, 255), width=2)
            draw.arc([4, 7, 12, 9], 0, 180, fill=(0, 0, 255), width=1)
            draw.ellipse([7, 8, 9, 10], fill=(0, 0, 255))
        elif name == "wifi_manager":
            # Draw wifi with settings gear
            draw.arc([2, 6, 14, 10], 0, 180, fill=(0, 150, 255), width=2)
            draw.ellipse([12, 2, 15, 5], outline=(100, 100, 100), width=1)
            draw.ellipse([13, 3, 14, 4], fill=(100, 100, 100))
        elif name == "other_features":
            # Draw a settings gear
            draw.ellipse([5, 5, 11, 11], outline=(0, 0, 0), width=1)
            draw.ellipse([6, 6, 10, 10], fill=(128, 128, 128))
            # Add gear teeth
            draw.rectangle([7, 3, 9, 5], fill=(0, 0, 0))
            draw.rectangle([7, 11, 9, 13], fill=(0, 0, 0))
            draw.rectangle([3, 7, 5, 9], fill=(0, 0, 0))
            draw.rectangle([11, 7, 13, 9], fill=(0, 0, 0))
        elif name == "read_files":
            # Draw a document with lines
            draw.rectangle([4, 2, 11, 14], outline=(0, 0, 0), width=1, fill=(255, 255, 255))
            draw.polygon([(11, 2), (11, 5), (8, 5)], fill=(200, 200, 200))
            draw.line([5, 7, 10, 7], fill=(0, 0, 0))
            draw.line([5, 9, 9, 9], fill=(0, 0, 0))
            draw.line([5, 11, 10, 11], fill=(0, 0, 0))
        elif name == "payload":
            # Draw code brackets with center dot
            draw.polygon([(3, 4), (5, 4), (4, 8), (5, 12), (3, 12), (2, 8)], fill=(0, 255, 0))
            draw.polygon([(13, 4), (11, 4), (12, 8), (11, 12), (13, 12), (14, 8)], fill=(0, 255, 0))
            draw.ellipse([7, 7, 9, 9], fill=(255, 0, 0))
        else:
            # Default: draw a simple square
            draw.rectangle([4, 4, 12, 12], fill=(128, 128, 128))
        
        # Convert to RGB for better LCD compatibility
        rgb_img = Image.new('RGB', size, (255, 255, 255))
        rgb_img.paste(img, (0, 0), img)
        rgb_img.save(png_path)
        print(f"✓ Created {png_path}")
        return True
    except Exception as e:
        print(f"✗ Error creating {png_path}: {e}")
        return False

def main():
    print("Creating PNG icons for RaspyJack menu...")
    
    # Create PNG directory
    png_dir = "/root/Raspyjack/icons/png"
    os.makedirs(png_dir, exist_ok=True)
    
    # Icon names matching the menu items
    icons_to_create = [
        "scan_nmap",
        "reverse_shell", 
        "responder",
        "mitm_sniff",
        "dns_spoofing",
        "network_info",
        "wifi_manager",
        "other_features",
        "read_files",
        "payload"
    ]
    
    # Create PNG icons
    success_count = 0
    for icon_name in icons_to_create:
        png_path = f"{png_dir}/{icon_name}.png"
        if create_icon_png(icon_name, png_path, size=(16, 16)):
            success_count += 1
    
    print(f"\n✓ Successfully created {success_count}/{len(icons_to_create)} icons")
    print(f"Icons saved to: {png_dir}")
    print("\nYou can now run RaspyJack with the new bitmap icons!")

if __name__ == "__main__":
    main() 