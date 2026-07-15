from pathlib import Path
import argparse

from parser import parse_file
from exporter import (
    export_json,
    export_csv,
    export_txt,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="IOC Processing Utility"
    )

    parser.add_argument(
        "input",
        help="Input text file containing one IOC per line",
    )

    parser.add_argument(
        "--format",
        choices=["json", "csv", "txt"],
        default="json",
        help="Export format",
    )

    parser.add_argument(
        "--output",
        default="output",
        help="Output directory",
    )

    args = parser.parse_args()

    iocs = parse_file(args.input)

    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)

    match args.format:

        case "json":
            export_json(iocs, output_dir / "iocs.json")

        case "csv":
            export_csv(iocs, output_dir / "iocs.csv")

        case "txt":
            export_txt(iocs, output_dir / "iocs.txt")

    print(f"Processed {len(iocs)} unique IOC(s).")
    print(f"Output written to: {output_dir.resolve()}")


if __name__ == "__main__":
    main()