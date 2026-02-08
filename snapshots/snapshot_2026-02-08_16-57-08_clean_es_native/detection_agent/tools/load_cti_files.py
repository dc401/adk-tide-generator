"""load and parse CTI files with intelligent chunking (ported from gcphunter)"""

from pathlib import Path
from google.genai.types import Part
from google.genai import Client
import os
import re
import time

#conservative token budget - leaves room for agent reasoning
MAX_TOTAL_TOKENS = 400000  #400k tokens for CTI files
CHARS_PER_TOKEN = 4
MAX_FILE_SIZE = 50 * 1024 * 1024  #50MB safety limit

def estimate_tokens(text_or_bytes) -> int:
    """estimate token count"""
    if isinstance(text_or_bytes, int):
        return (text_or_bytes * 2) // CHARS_PER_TOKEN
    if isinstance(text_or_bytes, bytes):
        return (len(text_or_bytes) * 2) // CHARS_PER_TOKEN
    if isinstance(text_or_bytes, str):
        return len(text_or_bytes) // CHARS_PER_TOKEN
    return 0

def validate_cti_file(file_path: Path) -> bool:
    """validate file is safe to process"""
    #check file size
    if file_path.stat().st_size > MAX_FILE_SIZE:
        raise ValueError(f"File too large: {file_path}")

    #block path traversal
    if '..' in str(file_path) or file_path.is_symlink():
        raise ValueError(f"Invalid path: {file_path}")

    #only allow these file types
    ALLOWED_EXTENSIONS = {'.pdf', '.txt', '.md', '.docx'}
    if file_path.suffix.lower() not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Wrong file type: {file_path.suffix}")

    return True

def sanitize_cti_content(text: str) -> str:
    """strip out suspicious patterns from CTI content"""
    injection_patterns = [
        r'ignore previous instructions',
        r'disregard.*system prompt',
        r'act as.*different',
        r'system:\s*you are now',
    ]

    for pattern in injection_patterns:
        text = re.sub(pattern, '[REDACTED]', text, flags=re.IGNORECASE)

    return text

def chunk_text(text: str, chunk_size_chars: int = 200000) -> list:
    """split text on paragraph boundaries"""
    paragraphs = re.split(r'\n\s*\n', text)
    chunks = []
    current_chunk = []
    current_size = 0

    for para in paragraphs:
        para_size = len(para)
        if current_size + para_size > chunk_size_chars and current_chunk:
            chunks.append('\n\n'.join(current_chunk))
            current_chunk = [para]
            current_size = para_size
        else:
            current_chunk.append(para)
            current_size += para_size

    if current_chunk:
        chunks.append('\n\n'.join(current_chunk))

    return chunks

def summarize_chunk(chunk_text: str, file_name: str, chunk_num: int, total_chunks: int) -> str:
    """summarize a single chunk of text"""
    try:
        client = Client(
            vertexai=True,
            project=os.environ.get('GOOGLE_CLOUD_PROJECT'),
            location=os.environ.get('GOOGLE_CLOUD_LOCATION')
        )

        #sanitize before processing
        chunk_text = sanitize_cti_content(chunk_text)

        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=[
                f"Extract threat intelligence from this CTI document chunk ({chunk_num}/{total_chunks} from {file_name}).\n\n"
                f"Extract:\n"
                f"- Threat actors/groups\n"
                f"- TTPs and MITRE ATT&CK techniques\n"
                f"- IOCs (IPs, domains, hashes, file paths)\n"
                f"- GCP/cloud-specific details\n"
                f"- Attack chains and procedures\n\n"
                f"Be detailed and preserve technical specifics.\n\n{chunk_text}"
            ]
        )

        time.sleep(0.8)  #throttle after API call
        return response.text
    except Exception as e:
        return f"[Summarization error: {str(e)}]"

def summarize_file_chunked(file_path: Path, file_type: str, file_bytes: bytes) -> str:
    """summarize large files in chunks for better coverage"""
    try:
        client = Client(
            vertexai=True,
            project=os.environ.get('GOOGLE_CLOUD_PROJECT'),
            location=os.environ.get('GOOGLE_CLOUD_LOCATION')
        )

        mime_types = {
            'pdf': 'application/pdf',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        }

        #extract text first
        extract_response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=[
                Part(text=f"Extract all text from this {file_type.upper()} file. Preserve structure and formatting."),
                Part(inline_data={'mime_type': mime_types[file_type], 'data': file_bytes})
            ]
        )

        time.sleep(0.5)  #throttle after API call
        extracted_text = extract_response.text

        #sanitize extracted content
        extracted_text = sanitize_cti_content(extracted_text)

        #chunk the extracted text
        chunks = chunk_text(extracted_text, chunk_size_chars=200000)

        summaries = []
        for i, chunk in enumerate(chunks[:5], 1):  #limit to first 5 chunks
            summary = summarize_chunk(chunk, file_path.name, i, len(chunks))
            summaries.append(f"--- Chunk {i}/{len(chunks)} ---\n{summary}\n")

            if i < min(5, len(chunks)):
                time.sleep(2)  #delay between chunks

        combined = '\n'.join(summaries)

        if len(chunks) > 5:
            combined += f"\n[Note: File had {len(chunks)} chunks, summarized first 5 for token efficiency]\n"

        return f"\n{'='*80}\nFILE: {file_path.name} (CHUNKED SUMMARY)\n{'='*80}\n{combined}\n"

    except Exception as e:
        return f"\n[ERROR summarizing {file_path.name}: {str(e)}]\n"

def load_cti_files(folder_path: str = 'cti_src') -> dict:
    """
    load and parse CTI files with intelligent chunking.
    stays within 400k token budget for CTI content.

    Args:
        folder_path: path to directory containing CTI files

    Returns:
        dict: {
            "files_loaded": int,
            "text_content": str,
            "file_parts": [Part objects]
        }
    """
    cti_folder = Path(folder_path)

    if not cti_folder.exists():
        return {
            "files_loaded": 0,
            "text_content": f"ERROR: CTI folder not found: {folder_path}",
            "file_parts": []
        }

    if not cti_folder.is_dir():
        return {
            "files_loaded": 0,
            "text_content": f"ERROR: Not a directory: {folder_path}",
            "file_parts": []
        }

    supported_extensions = {'.txt', '.md', '.pdf', '.docx'}

    text_parts = []
    file_parts = []
    files_loaded = 0
    total_tokens = 0
    files_summarized = 0

    #collect and sort files by size (process smaller first)
    file_list = []
    for file_path in sorted(cti_folder.iterdir()):
        if file_path.is_file() and file_path.suffix.lower() in supported_extensions:
            try:
                validate_cti_file(file_path)  #security check
                file_size = file_path.stat().st_size
                estimated_tokens = estimate_tokens(file_size)
                file_list.append((file_path, file_size, estimated_tokens))
            except ValueError as e:
                text_parts.append(f"\n[Skipping {file_path.name}: {e}]\n")

    file_list.sort(key=lambda x: x[1])  #small files first

    for file_path, file_size, estimated_tokens in file_list:
        file_ext = file_path.suffix.lower()

        #check if we're approaching token limit
        if total_tokens > MAX_TOTAL_TOKENS:
            text_parts.append(f"\n[Skipping {file_path.name} - token budget exhausted]\n")
            continue

        #text files
        if file_ext in {'.txt', '.md'}:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read().strip()
                    if not content:
                        continue

                    #sanitize content
                    content = sanitize_cti_content(content)

                    content_tokens = estimate_tokens(content)

                    #if file is large, chunk and summarize
                    if content_tokens > 50000:
                        chunks = chunk_text(content)
                        summaries = []
                        for i, chunk in enumerate(chunks[:5], 1):
                            summary = summarize_chunk(chunk, file_path.name, i, len(chunks))
                            summaries.append(f"--- Chunk {i} ---\n{summary}\n")

                            if i < min(5, len(chunks)):
                                time.sleep(2)

                        combined = '\n'.join(summaries)
                        text_parts.append(
                            f"\n{'='*80}\nFILE: {file_path.name} (CHUNKED SUMMARY)\n{'='*80}\n{combined}\n"
                        )
                        total_tokens += estimate_tokens(combined)
                        files_summarized += 1
                    else:
                        #small enough to include directly
                        text_parts.append(f"\n{'='*80}\nFILE: {file_path.name}\n{'='*80}\n{content}\n")
                        total_tokens += content_tokens

                    files_loaded += 1
            except Exception as e:
                text_parts.append(f"\n[ERROR reading {file_path.name}: {str(e)}]\n")

        #PDF files
        elif file_ext == '.pdf':
            try:
                with open(file_path, 'rb') as f:
                    pdf_bytes = f.read()

                if not pdf_bytes:
                    continue

                #if small enough and under budget, attach directly
                if estimated_tokens < 50000 and (total_tokens + estimated_tokens) < MAX_TOTAL_TOKENS:
                    file_parts.append(Part(inline_data={'mime_type': 'application/pdf', 'data': pdf_bytes}))
                    text_parts.append(f"\n[PDF attached: {file_path.name}]\n")
                    total_tokens += estimated_tokens
                else:
                    #chunk and summarize
                    summary = summarize_file_chunked(file_path, 'pdf', pdf_bytes)
                    text_parts.append(summary)
                    total_tokens += estimate_tokens(summary)
                    files_summarized += 1

                files_loaded += 1
            except Exception as e:
                text_parts.append(f"\n[ERROR reading PDF {file_path.name}: {str(e)}]\n")

        #DOCX files
        elif file_ext == '.docx':
            try:
                with open(file_path, 'rb') as f:
                    docx_bytes = f.read()

                if not docx_bytes:
                    continue

                if estimated_tokens < 50000 and (total_tokens + estimated_tokens) < MAX_TOTAL_TOKENS:
                    file_parts.append(Part(inline_data={
                        'mime_type': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                        'data': docx_bytes
                    }))
                    text_parts.append(f"\n[DOCX attached: {file_path.name}]\n")
                    total_tokens += estimated_tokens
                else:
                    summary = summarize_file_chunked(file_path, 'docx', docx_bytes)
                    text_parts.append(summary)
                    total_tokens += estimate_tokens(summary)
                    files_summarized += 1

                files_loaded += 1
            except Exception as e:
                text_parts.append(f"\n[ERROR reading DOCX {file_path.name}: {str(e)}]\n")

    summary = (
        f"Loaded {files_loaded} CTI files (~{total_tokens:,} tokens)\n"
        f"Files chunked/summarized: {files_summarized}\n"
        f"Remaining token budget for analysis: ~{1048576 - total_tokens:,} tokens\n"
        f"{'='*80}\n"
    )

    return {
        "files_loaded": files_loaded,
        "text_content": summary + "".join(text_parts),
        "file_parts": file_parts
    }
