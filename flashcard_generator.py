#!/usr/bin/env python3
"""
Flashcard Generator for Countries and Flags
Generates a PDF with country names on one side and flags on the other for printing and cutting.
"""

import os
import requests
from reportlab.lib.pagesizes import letter, A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader
from PIL import Image
import io

# Country data: Armenia + top 7 countries by GDP + additional countries
COUNTRIES = [
    {"name": "Armenia", "code": "am"},
    {"name": "United States", "code": "us"},
    {"name": "China", "code": "cn"},
    {"name": "Germany", "code": "de"},
    {"name": "Japan", "code": "jp"},
    {"name": "India", "code": "in"},
    {"name": "United Kingdom", "code": "gb"},
    {"name": "France", "code": "fr"},
    {"name": "Georgia", "code": "ge"},
    {"name": "Canada", "code": "ca"},
    {"name": "Mexico", "code": "mx"},
    {"name": "Italy", "code": "it"}
]

class FlashcardGenerator:
    def __init__(self, page_size=letter):
        self.page_size = page_size
        self.page_width, self.page_height = page_size
        self.card_width = 2.5 * inch
        self.card_height = 1.5 * inch
        self.margin = 0.5 * inch
        
        # Calculate cards per page
        self.cards_per_row = int((self.page_width - 2 * self.margin) // self.card_width)
        self.cards_per_col = int((self.page_height - 2 * self.margin) // self.card_height)
        self.cards_per_page = self.cards_per_row * self.cards_per_col
        
    def download_flag(self, country_code):
        """Download flag image from flagpedia.net"""
        url = f"https://flagpedia.net/data/flags/w580/{country_code}.png"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return Image.open(io.BytesIO(response.content))
        except Exception as e:
            print(f"Failed to download flag for {country_code}: {e}")
            return None
    
    def create_placeholder_flag(self, country_name):
        """Create a simple placeholder flag image"""
        img = Image.new('RGB', (580, 387), color='lightgray')
        return img
    
    def draw_card_borders(self, c, x, y):
        """Draw dotted border around card for cutting guides"""
        c.setDash(2, 2)
        c.setStrokeColor('gray')
        c.rect(x, y, self.card_width, self.card_height)
        c.setDash(1, 0)  # Reset to solid line
    
    def draw_country_name(self, c, country_name, x, y):
        """Draw country name centered on card"""
        c.setFont("Helvetica-Bold", 16)
        c.setFillColor('black')
        
        # Center text on card
        text_width = c.stringWidth(country_name, "Helvetica-Bold", 16)
        text_x = x + (self.card_width - text_width) / 2
        text_y = y + self.card_height / 2 - 8
        
        c.drawString(text_x, text_y, country_name)
    
    def draw_flag_image(self, c, flag_image, x, y):
        """Draw flag image centered on card"""
        if flag_image is None:
            return
            
        # Resize image to fit card with padding
        max_width = self.card_width - 0.2 * inch
        max_height = self.card_height - 0.2 * inch
        
        # Calculate scaling to maintain aspect ratio
        img_width, img_height = flag_image.size
        scale_w = max_width / img_width
        scale_h = max_height / img_height
        scale = min(scale_w, scale_h)
        
        new_width = img_width * scale
        new_height = img_height * scale
        
        # Center image on card
        img_x = x + (self.card_width - new_width) / 2
        img_y = y + (self.card_height - new_height) / 2
        
        # Convert PIL image to ImageReader for reportlab
        img_buffer = io.BytesIO()
        flag_image.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        img_reader = ImageReader(img_buffer)
        
        c.drawImage(img_reader, img_x, img_y, new_width, new_height)
    
    def generate_pdf(self, filename="country_flashcards.pdf"):
        """Generate the complete flashcard PDF"""
        c = canvas.Canvas(filename, pagesize=self.page_size)
        
        # Download all flags first
        print("Downloading flags...")
        flags = {}
        for country in COUNTRIES:
            flag = self.download_flag(country["code"])
            if flag is None:
                flag = self.create_placeholder_flag(country["name"])
            flags[country["code"]] = flag
        
        # Calculate pages needed
        total_countries = len(COUNTRIES)
        pages_needed = (total_countries + self.cards_per_page - 1) // self.cards_per_page
        
        # Generate country name pages
        for page in range(pages_needed):
            print(f"Generating names page {page + 1}...")
            c.setFont("Helvetica", 10)
            c.drawString(self.margin, self.page_height - self.margin/2, 
                        f"Country Names - Page {page + 1} - Print double-sided, then cut along dotted lines")
            
            start_idx = page * self.cards_per_page
            end_idx = min(start_idx + self.cards_per_page, total_countries)
            
            for i in range(start_idx, end_idx):
                card_pos = i - start_idx
                row = card_pos // self.cards_per_row
                col = card_pos % self.cards_per_row
                
                x = self.margin + col * self.card_width
                y = self.page_height - self.margin - (row + 1) * self.card_height
                
                # Don't draw borders on name pages to avoid alignment sensitivity
                self.draw_country_name(c, COUNTRIES[i]["name"], x, y)
            
            c.showPage()
        
        # Generate flag pages (mirrored for double-sided printing)
        for page in range(pages_needed):
            print(f"Generating flags page {page + 1}...")
            c.drawString(self.margin, self.page_height - self.margin/2, 
                        f"Country Flags - Page {page + 1} - Back side")
            
            start_idx = page * self.cards_per_page
            end_idx = min(start_idx + self.cards_per_page, total_countries)
            
            for i in range(start_idx, end_idx):
                card_pos = i - start_idx
                row = card_pos // self.cards_per_row
                # Mirror the column order for proper double-sided alignment
                col = (self.cards_per_row - 1) - (card_pos % self.cards_per_row)
                
                x = self.margin + col * self.card_width
                y = self.page_height - self.margin - (row + 1) * self.card_height
                
                self.draw_card_borders(c, x, y)
                self.draw_flag_image(c, flags[COUNTRIES[i]["code"]], x, y)
            
            c.showPage()
        
        c.save()
        print(f"PDF generated: {filename}")
        return filename

def main():
    generator = FlashcardGenerator()
    
    print("Country Flashcard Generator")
    print("Countries included:")
    for country in COUNTRIES:
        print(f"  - {country['name']}")
    
    filename = generator.generate_pdf()
    
    print(f"\nFlashcards generated successfully!")
    print(f"File: {filename}")
    print("\nPrinting instructions:")
    print("1. Print the PDF double-sided (flip on long edge)")
    print("2. Cut along the dotted lines")
    print("3. You'll have flashcards with country names on one side and flags on the other")

if __name__ == "__main__":
    main()