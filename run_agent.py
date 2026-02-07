#!/usr/bin/env python3
"""
CLI entry point for sigma detection agent

usage:
    python run_agent.py --interactive
    python run_agent.py --cti-folder path/to/cti --output generated/
"""

import asyncio
import argparse
import sys
from pathlib import Path

#load environment from .env file
from dotenv import load_dotenv
load_dotenv()

from sigma_detection_agent.agent import run_sigma_detection_agent
from sigma_detection_agent.iterative_runner import run_iterative_pipeline

def parse_args():
    """parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Sigma Detection Agent - Automated SIEM Detection Engineering',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # interactive mode with defaults
  python run_agent.py --interactive

  # specify CTI folder and output directory
  python run_agent.py --cti-folder cti_src --output generated/

  # test CTI loading only
  python run_agent.py --test-cti

phases:
  Phase 1: Foundation (COMPLETE) - schemas, CTI loading, agent skeleton
  Phase 2: Sigma generation (TODO) - CTI → Sigma rules
  Phase 3: Test generation (TODO) - TP/FN/FP/TN payloads
  Phase 4-10: Testing, validation, deployment
        """
    )

    parser.add_argument(
        '--interactive',
        action='store_true',
        help='run in interactive mode with prompts'
    )

    parser.add_argument(
        '--cti-folder',
        type=str,
        default='cti_src',
        help='path to CTI files folder (default: cti_src)'
    )

    parser.add_argument(
        '--output',
        type=str,
        default='generated',
        help='output directory for generated rules (default: generated/)'
    )

    parser.add_argument(
        '--test-cti',
        action='store_true',
        help='test CTI file loading only (Phase 1 validation)'
    )

    parser.add_argument(
        '--max-retries',
        type=int,
        default=3,
        help='max session retry attempts for quota handling (default: 3)'
    )

    parser.add_argument(
        '--iterative',
        action='store_true',
        help='use iterative refinement mode (2-3 iterations per agent) - RECOMMENDED'
    )

    return parser.parse_args()

async def test_cti_loading(cti_folder: str):
    """test CTI file loading (Phase 1 validation)"""
    from sigma_detection_agent.tools import load_cti_files

    print("="*80)
    print("Testing CTI File Loading (Phase 1 Validation)")
    print("="*80)

    print(f"\nCTI Folder: {cti_folder}")

    #check folder exists
    if not Path(cti_folder).exists():
        print(f"ERROR: CTI folder not found: {cti_folder}")
        print("\nCreate the folder and add CTI files:")
        print(f"  mkdir -p {cti_folder}")
        print(f"  cp your-threat-intel.pdf {cti_folder}/")
        return False

    #load files
    print("\nLoading CTI files...")
    result = load_cti_files(cti_folder)

    print(f"\nResults:")
    print(f"  Files loaded: {result['files_loaded']}")
    print(f"  File parts: {len(result['file_parts'])}")

    if result['files_loaded'] == 0:
        print("\n⚠ No CTI files found!")
        print(f"\nSupported formats: .txt, .md, .pdf, .docx")
        print(f"Place files in: {cti_folder}/")
        return False

    #preview content
    print(f"\nContent preview (first 500 chars):")
    print("-"*80)
    print(result['text_content'][:500])
    print("-"*80)

    print("\n✓ CTI loading successful!")
    print("\nPhase 1 (Foundation) validation: PASSED")
    return True

async def interactive_mode(args):
    """interactive mode with prompts"""
    print("="*80)
    print("Sigma Detection Agent - Interactive Mode")
    print("="*80)

    #check CTI folder
    cti_folder = Path(args.cti_folder)
    if not cti_folder.exists():
        print(f"\n⚠ CTI folder not found: {args.cti_folder}")
        create = input("\nCreate folder? (y/n): ").strip().lower()
        if create == 'y':
            cti_folder.mkdir(parents=True, exist_ok=True)
            print(f"✓ Created: {args.cti_folder}")
            print(f"\nNext: Add CTI files to {args.cti_folder}/")
            print("Supported formats: .txt, .md, .pdf, .docx")
            return
        else:
            print("Exiting...")
            return

    #check for CTI files
    cti_files = list(cti_folder.glob('*'))
    cti_files = [f for f in cti_files if f.suffix.lower() in {'.txt', '.md', '.pdf', '.docx'}]

    if not cti_files:
        print(f"\n⚠ No CTI files found in {args.cti_folder}")
        print("\nSupported formats: .txt, .md, .pdf, .docx")
        print(f"Add files to {args.cti_folder}/ and run again")
        return

    print(f"\nFound {len(cti_files)} CTI file(s):")
    for f in cti_files:
        print(f"  - {f.name}")

    #confirm run
    print(f"\nOutput directory: {args.output}")
    run = input("\nGenerate detection rules? (y/n): ").strip().lower()

    if run != 'y':
        print("Exiting...")
        return

    #run agent
    print("\n" + "="*80)
    print("Running Detection Agent Pipeline...")
    print("="*80)

    result = await run_sigma_detection_agent(
        cti_folder=args.cti_folder,
        output_dir=args.output,
        max_retries=args.max_retries
    )

    if result and result.get('success'):
        print("\n" + "="*80)
        print("✓ Detection Generation Complete!")
        print("="*80)
        print(f"\nSession file: {result['session_file']}")
        print(f"Generated rules: {args.output}/sigma_rules/")
        print(f"Test payloads: {args.output}/tests/")
    else:
        print("\n✗ Detection generation failed")
        print("Check logs above for errors")

async def main():
    """main entry point"""
    args = parse_args()

    #test CTI loading only
    if args.test_cti:
        success = await test_cti_loading(args.cti_folder)
        sys.exit(0 if success else 1)

    #interactive mode
    if args.interactive:
        await interactive_mode(args)
        return

    #non-interactive mode - run directly
    print("Running detection agent...")
    print(f"CTI folder: {args.cti_folder}")
    print(f"Output: {args.output}")
    print(f"Mode: {'Iterative (2-3 iterations per agent)' if args.iterative else 'Single-pass'}")

    #choose runner based on mode
    if args.iterative:
        result = await run_iterative_pipeline(
            cti_folder=args.cti_folder,
            output_dir=args.output
        )
    else:
        result = await run_sigma_detection_agent(
            cti_folder=args.cti_folder,
            output_dir=args.output,
            max_retries=args.max_retries
        )

    if result and result.get('success'):
        print(f"\n✓ Success! Session file: {result['session_file']}")
        sys.exit(0)
    else:
        print("\n✗ Failed")
        sys.exit(1)

if __name__ == '__main__':
    asyncio.run(main())
