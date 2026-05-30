import asyncio
import json
import shutil


async def run_command_json_lines(command: list[str], input_text: str | None = None) -> list[dict]:
    process = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE if input_text is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate(
        input_text.encode("utf-8") if input_text is not None else None
    )

    if process.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(command)} :: {stderr.decode('utf-8', errors='ignore').strip()}"
        )

    rows: list[dict] = []
    for line in stdout.decode("utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            rows.append({"raw": line})

    return rows


def ensure_binary(name: str) -> str:
    binary = shutil.which(name)
    if not binary:
        raise FileNotFoundError(f"Missing binary: {name}")
    return binary


async def run_subfinder(domain: str) -> list[dict]:
    binary = ensure_binary("subfinder")
    return await run_command_json_lines([binary, "-silent", "-json", "-d", domain])


async def run_httpx(hosts: list[str]) -> list[dict]:
    binary = ensure_binary("httpx")
    input_text = "\n".join(hosts) + "\n" if hosts else ""
    return await run_command_json_lines([binary, "-silent", "-json"], input_text=input_text)


async def run_naabu(hosts: list[str]) -> list[dict]:
    binary = ensure_binary("naabu")
    input_text = "\n".join(hosts) + "\n" if hosts else ""
    return await run_command_json_lines([binary, "-silent", "-json"], input_text=input_text)