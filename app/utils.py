import os
import aiofiles
import json
import models as m


async def scan_directory_for_json_files(directory: str) -> list:
    json_files = []

    async def scan_dir(dir_path: str):
        for entry in os.scandir(dir_path):
            if entry.is_dir():
                await scan_dir(entry.path)
            elif entry.is_file() and entry.name.endswith('.json'):
                json_files.append(entry.path)

    await scan_dir(directory)
    return json_files


async def read_file(file_path: str) -> dict:
    async with aiofiles.open(file_path, mode='r') as file:
        data = await file.read()
        return json.loads(data)


async def create_cve_record(data: dict) -> m.CVERecord:
    return m.CVERecord.from_dict(data)


async def create_problem_type(data: dict, cve_record: m.CVERecord) -> m.ProblemType:
    return m.ProblemType.from_dict(data, cve_record)


async def create_reference(data: dict, cve_record: m.CVERecord) -> m.Reference:
    return m.Reference.from_dict(data, cve_record)
