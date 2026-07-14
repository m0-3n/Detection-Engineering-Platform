import csv
import json
from pathlib import Path
from dataclasses import asdict

from models import IOC


def export_json(iocs: list[IOC], output_file: str) -> None:
    """
    Export IOCs to a JSON file.
    """

    data = []

    for ioc in iocs:
        item = asdict(ioc)
        item["ioc_type"] = ioc.ioc_type.value
        data.append(item)

    Path(output_file).write_text(
        json.dumps(data, indent=4),
        encoding="utf-8",
    )


def export_csv(iocs: list[IOC], output_file: str) -> None:
    """
    Export IOCs to CSV.
    """

    with open(output_file, "w", newline="", encoding="utf-8") as file:

        writer = csv.writer(file)

        writer.writerow(["value", "ioc_type", "is_valid"])

        for ioc in iocs:

            writer.writerow(
                [
                    ioc.value,
                    ioc.ioc_type.value,
                    ioc.is_valid,
                ]
            )


def export_txt(iocs: list[IOC], output_file: str) -> None:
    """
    Export IOCs as plain text.
    """

    with open(output_file, "w", encoding="utf-8") as file:

        for ioc in iocs:

            file.write(f"{ioc.value}\n")