from argparse import ArgumentParser
import asyncio
import utils as u
from database import async_session, engine
import models as m
import sys

BATCH_SIZE = 1000


async def process_files(file_paths: list, semaphore: asyncio.Semaphore) -> None:
    async with semaphore:
        tasks = [u.read_file(file_path) for file_path in file_paths]
        results = await asyncio.gather(*tasks)

        cve_records, problem_types, references = [], [], []

        for result in results:
            cve_record = await process_cve_record(result)
            cve_records.append(cve_record)
            problem_types.extend(await process_problem_types(result, cve_record))
            references.extend(await process_references(result, cve_record))

        await save_to_database(cve_records, problem_types, references)


async def process_cve_record(result: dict) -> m.CVERecord:
    return await u.create_cve_record(result.get("cveMetadata"))


async def process_problem_types(result: dict, cve_record: m.CVERecord) -> list:
    problem_types = []
    for problem_type_data in result.get("containers", {}).get("cna", {}).get("problemTypes", []):
        for description in problem_type_data.get("descriptions", []):
            problem_type = await u.create_problem_type(description, cve_record)
            problem_types.append(problem_type)
    return problem_types


async def process_references(result: dict, cve_record: m.CVERecord) -> list:
    references = []
    for reference_data in result.get("containers", {}).get("cna", {}).get("references", []):
        reference = await u.create_reference(reference_data, cve_record)
        references.append(reference)
    return references


async def save_to_database(cve_records, problem_types, references) -> None:
    async with async_session(engine()) as session:
        async with session.begin():
            session.add_all(cve_records)
            session.add_all(problem_types)
            session.add_all(references)


async def main(path: str) -> None:
    semaphore = asyncio.Semaphore(10)
    json_files = await u.scan_directory_for_json_files(path)
    tasks = []

    # Split the json_files into batches
    for i in range(0, len(json_files), BATCH_SIZE):
        batch_files = json_files[i:i + BATCH_SIZE]
        tasks.append(process_files(batch_files, semaphore))

    await asyncio.gather(*tasks)


if __name__ == "__main__":
    try:
        parser = ArgumentParser(description="App")
        parser.add_argument("--dir_path", type=str, help="Directory path")
        args = parser.parse_args()
        dir_path = args.dir_path
        asyncio.run(main(dir_path))
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
