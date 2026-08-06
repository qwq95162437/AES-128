from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve()
PROJECT_DIR = SCRIPT_PATH.parents[1]
WORKSPACE_DIR = PROJECT_DIR.parent
DATA_DIR = PROJECT_DIR / "data"
RESULTS_DIR = PROJECT_DIR / "results"
DEFAULT_SOURCE = (
    WORKSPACE_DIR
    / "AES_128_Project_3.0"
    / "AES_128_Project.sim"
    / "sim_1"
    / "behav"
    / "xsim"
    / "fault_dataset.csv"
)
TARGET_DATASET = DATA_DIR / "fault_dataset.csv"
PIPELINE_SCRIPTS = [
    PROJECT_DIR / "classification.py",
    PROJECT_DIR / "dfa_recover_god.py",
    PROJECT_DIR / "dfa_recover_attacker.py",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sync Vivado fault data into the Python project and run the analysis pipeline."
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=DEFAULT_SOURCE,
        help="Path to the Vivado-generated fault_dataset.csv.",
    )
    parser.add_argument(
        "--no-sync",
        action="store_true",
        help="Skip dataset sync and use the existing data/fault_dataset.csv.",
    )
    parser.add_argument(
        "--sync-only",
        action="store_true",
        help="Sync the dataset but do not run the analysis scripts.",
    )
    return parser.parse_args()


def sync_dataset(source: Path, target: Path) -> None:
    source = source.resolve()
    target = target.resolve()

    if not source.exists():
        raise FileNotFoundError(f"Dataset source not found: {source}")

    target.parent.mkdir(exist_ok=True)

    if source != target:
        shutil.copy2(source, target)
        print(f"[sync] copied dataset to {target}")
    else:
        print(f"[sync] source already matches target: {target}")


def run_script(script_path: Path) -> None:
    print(f"[run] {script_path.name}")
    subprocess.run(
        [sys.executable, str(script_path)],
        cwd=str(PROJECT_DIR),
        check=True,
    )


def main() -> int:
    args = parse_args()

    DATA_DIR.mkdir(exist_ok=True)
    RESULTS_DIR.mkdir(exist_ok=True)

    if not args.no_sync:
        sync_dataset(args.source, TARGET_DATASET)
    else:
        print(f"[sync] skipped, using existing dataset at {TARGET_DATASET}")

    if args.sync_only:
        print("[done] sync completed, analysis not started")
        return 0

    for script_path in PIPELINE_SCRIPTS:
        run_script(script_path)

    print(f"[done] analysis outputs are in {RESULTS_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
