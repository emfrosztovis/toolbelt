# Written by Gemini 3 Pro

import cv2
import numpy as np
import argparse
import os
import glob

def get_crop_boundary(edge_region, axis, tolerance=5):
    """
    Determines how many rows/cols to crop from an edge region.
    
    Args:
        edge_region: A slice of the image corresponding to the max crop area (N pixels).
        axis: 1 to check rows (for top/bottom), 0 to check cols (for left/right).
        tolerance: Pixel value tolerance for 'black' (0-tol) or 'white' (255-tol).
        
    Returns:
        int: The number of lines to crop.
    """
    if edge_region.size == 0:
        return 0

    # 1. Check for Black: All pixels in the line must be <= tolerance
    is_black = np.all(edge_region <= tolerance, axis=axis)
    
    # 2. Check for White: All pixels in the line must be >= 255 - tolerance
    is_white = np.all(edge_region >= 255 - tolerance, axis=axis)
    
    # Combine: A line is a border if it is essentially solid black OR solid white
    is_border = np.logical_or(is_black, is_white)

    # 3. Find the first line that is NOT a border
    # np.argmin returns the index of the first False value. 
    # If all are True (all border), it returns 0, so we check explicitly.
    if np.all(is_border):
        return len(is_border)
    else:
        return np.argmin(is_border)

def process_file(filepath, max_n, tolerance, overwrite):
    # 1. Read Image
    img = cv2.imread(filepath)
    if img is None:
        print(f"[SKIP] Corrupt or missing: {filepath}")
        return

    h, w = img.shape[:2]
    
    # 2. Prepare Grayscale for analysis
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY) if len(img.shape) == 3 else img

    # 3. Analyze Edges
    # We slice the array to get just the edge regions.
    # [Top]
    t_crop = get_crop_boundary(gray[:min(max_n, h), :], axis=1, tolerance=tolerance)
    
    # [Bottom] Reverse array (::-1) to scan from bottom-up
    b_crop = get_crop_boundary(gray[max(0, h-max_n):, :][::-1], axis=1, tolerance=tolerance)
    
    # [Left]
    l_crop = get_crop_boundary(gray[:, :min(max_n, w)], axis=0, tolerance=tolerance)
    
    # [Right] Reverse array (::-1) to scan from right-to-left
    r_crop = get_crop_boundary(gray[:, max(0, w-max_n):][:, ::-1], axis=0, tolerance=tolerance)

    # 4. Validation
    if t_crop == 0 and b_crop == 0 and l_crop == 0 and r_crop == 0:
        print(f"[NO CROP] {os.path.basename(filepath)}")
        return

    if (t_crop + b_crop >= h) or (l_crop + r_crop >= w):
        print(f"[   SKIP] Crop would remove entire image: {filepath}")
        return

    # 5. Apply Crop
    # Slicing: array[start_row : end_row, start_col : end_col]
    cropped_img = img[t_crop + 1 : h - b_crop - 1, l_crop + 1 : w - r_crop - 1]

    # 6. Save
    directory, filename = os.path.split(filepath)
    name, ext = os.path.splitext(filename)
    
    if overwrite:
        out_path = filepath
    else:
        out_path = os.path.join(directory, f"cropped_{name}{ext}")

    cv2.imwrite(out_path, cropped_img)
    print(f"[     OK] {filename} -> T:{t_crop} B:{b_crop} L:{l_crop} R:{r_crop}")

def main():
    parser = argparse.ArgumentParser(description="Batch crop black/white edges.")
    parser.add_argument('files', nargs='+', help='Image files (supports wildcards)')
    parser.add_argument('-n', '--max-pixels', type=int, default=100, help='Max pixels to check per side')
    parser.add_argument('-t', '--tolerance', type=int, default=10, help='Tolerance for black/white (0-255)')
    parser.add_argument('--overwrite', action='store_true', help='Overwrite original files')

    args = parser.parse_args()

    # Expand wildcards (shell usually does this, but this handles Windows cmd quirks)
    file_list = []
    for f in args.files:
        expanded = glob.glob(f)
        if expanded:
            file_list.extend(expanded)
        else:
            # If glob returns nothing, it might be a specific file that doesn't exist 
            # or a direct filename without wildcards.
            file_list.append(f)

    # Process
    print(f"Processing {len(file_list)} files with N={args.max_pixels}...")
    for f in file_list:
        process_file(f, args.max_pixels, args.tolerance, args.overwrite)

if __name__ == "__main__":
    main()
