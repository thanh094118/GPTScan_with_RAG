#!/usr/bin/env python3
"""
upload_batch_khoj.py - Upload files theo lô để tránh bị ghi đè
"""

import requests
import os
import time
from pathlib import Path
from typing import List

# --- CẤU HÌNH ---
BASE_URL = "http://localhost:42110"
# Endpoint này nhận PUT nhưng hỗ trợ multipart list
UPLOAD_ENDPOINT = f"{BASE_URL}/api/content" 
AUDIT_DIR = Path("./audit_reports")
FILE_PATTERNS = ["*.pdf", "*.txt", "*.md"]
BATCH_SIZE = 10  # Số lượng file gửi trong 1 lần request (để tránh quá tải RAM/Server)

# Token (Nếu bạn đã setup user/pass thì bắt buộc phải có)
# Để trống nếu dùng anonymous
API_TOKEN = "" 

def get_headers():
    headers = {}
    if API_TOKEN:
        headers["Authorization"] = f"Bearer {API_TOKEN}"
    return headers

def find_files(directory: Path, patterns: List[str]) -> List[Path]:
    files = []
    if not directory.exists():
        print(f"❌ Error: Directory '{directory}' not found!")
        return []
    for pattern in patterns:
        files.extend(directory.rglob(pattern))
    # Lọc bỏ file rác Windows
    return [f for f in files if not f.name.endswith(':Zone.Identifier')]

def upload_batch(files_batch: List[Path]) -> bool:
    """Upload một danh sách file trong 1 request duy nhất"""
    files_payload = []
    opened_files = [] # Giữ handle để close sau này

    try:
        # Chuẩn bị payload multipart/form-data
        # Cấu trúc: [('files', (filename, file_obj, mime_type)), ...]
        for file_path in files_batch:
            f = open(file_path, 'rb')
            opened_files.append(f)
            mime = get_mime_type(file_path)
            # Quan trọng: Key phải là 'files' (số nhiều) cho tất cả các mục
            files_payload.append(('files', (file_path.name, f, mime)))

        print(f"   🚀 Sending batch of {len(files_batch)} files...", end=" ", flush=True)
        
        # Gửi Request
        response = requests.put(
            UPLOAD_ENDPOINT, 
            files=files_payload, 
            headers=get_headers(),
            timeout=120 # Tăng timeout vì gửi nhiều file
        )

        if response.status_code == 200:
            print("✅ OK")
            return True
        else:
            print(f"❌ Failed: {response.status_code} - {response.text[:100]}")
            return False

    except Exception as e:
        print(f"❌ Error: {e}")
        return False
    finally:
        # Đóng tất cả file handle
        for f in opened_files:
            f.close()

def get_mime_type(file_path: Path) -> str:
    suffix = file_path.suffix.lower()
    return {
        '.pdf': 'application/pdf',
        '.txt': 'text/plain',
        '.md': 'text/markdown',
    }.get(suffix, 'application/octet-stream')

def main():
    print("=" * 70)
    print("KHOJ RAG - BATCH UPLOADER (FIX OVERWRITE)")
    print("=" * 70)

    all_files = find_files(AUDIT_DIR, FILE_PATTERNS)
    if not all_files:
        return

    print(f"📊 Found {len(all_files)} files.")
    
    # Chia files thành các batch nhỏ (Chunking)
    batches = [all_files[i:i + BATCH_SIZE] for i in range(0, len(all_files), BATCH_SIZE)]
    print(f"📦 Split into {len(batches)} batches (Size: {BATCH_SIZE})")

    if input("\nStart upload? (y/n): ").lower() != 'y':
        return

    success_batches = 0
    
    for i, batch in enumerate(batches, 1):
        print(f"\n📦 Batch {i}/{len(batches)}:")
        # In tên các file trong batch này để dễ theo dõi
        for f in batch:
            print(f"   - {f.name}")
            
        if upload_batch(batch):
            success_batches += 1
        
        # Nghỉ 1 chút để DB không bị lock
        time.sleep(1)

    print("\n" + "=" * 70)
    print(f"DONE! Successful batches: {success_batches}/{len(batches)}")
    print("Wait ~30s for indexing, then check DB again.")

if __name__ == "__main__":
    main()