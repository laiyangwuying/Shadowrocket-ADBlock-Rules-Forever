# -*- coding: utf-8 -*-
"""构建流水线公共工具：HTTP 拉取、列表读写、原子写入、计时日志。"""

from __future__ import annotations

import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Iterable, TypeVar

import requests

FACTORY_ROOT = Path(__file__).resolve().parent
RESULTANT_DIR = FACTORY_ROOT / 'resultant'

USER_AGENT = (
    'Mozilla/5.0 (compatible; Shadowrocket-ADBlock-Rules-Forever/build; +https://github.com/)'
)
DEFAULT_TIMEOUT = (12, 90)
DEFAULT_RETRIES = 5

T = TypeVar('T')


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def log_step(name: str) -> Callable[[], None]:
    """上下文计时器，用于 with 语句。"""
    class _Step:
        def __enter__(self):
            self.t0 = time.perf_counter()
            log(f'[{name}] start')
            return self

        def __exit__(self, *exc):
            log(f'[{name}] done in {time.perf_counter() - self.t0:.1f}s')
            return False

    return _Step()


def fetch_text(url: str, *, retries: int = DEFAULT_RETRIES) -> str:
    headers = {'User-Agent': USER_AGENT}
    last_status = 0
    for attempt in range(retries):
        try:
            r = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
            last_status = r.status_code
            if r.status_code == 200:
                r.encoding = r.apparent_encoding or 'utf-8'
                return r.text
        except requests.RequestException as exc:
            last_status = 0
            log(f'fetch retry {attempt + 1}/{retries} {url}: {exc}')
        time.sleep(min(2 ** attempt, 8))
    raise RuntimeError(f'fetch failed {url} (last status {last_status})')


def fetch_text_parallel(urls: Iterable[str], *, workers: int = 4) -> dict[str, str]:
    url_list = list(urls)
    out: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=min(workers, len(url_list) or 1)) as pool:
        futures = {pool.submit(fetch_text, u): u for u in url_list}
        for fut in as_completed(futures):
            url = futures[fut]
            out[url] = fut.result()
    return out


def run_parallel(tasks: dict[str, Callable[[], T]], *, workers: int | None = None) -> dict[str, T]:
    """并行执行多个构建步骤，返回 {name: result}。"""
    if not tasks:
        return {}
    w = workers or len(tasks)
    out: dict[str, T] = {}
    with ThreadPoolExecutor(max_workers=w) as pool:
        futures = {pool.submit(fn): name for name, fn in tasks.items()}
        for fut in as_completed(futures):
            name = futures[fut]
            out[name] = fut.result()
    return out


def read_lines(path: str | Path) -> list[str]:
    with open(path, 'r', encoding='utf-8') as fp:
        return fp.read().splitlines()


def read_entries(path: str | Path) -> list[str]:
    """读取列表文件：跳过空行与 # 注释，并 strip。"""
    entries: list[str] = []
    for line in read_lines(path):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        entries.append(line)
    return entries


def atomic_write(path: str | Path, content: str) -> None:
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + '.tmp')
    tmp.write_text(content, encoding='utf-8')
    tmp.replace(dest)


def write_list(path: str | Path, header: str, items: Iterable[str]) -> int:
    lines = sorted(set(items))
    body = header.rstrip('\n') + '\n' + '\n'.join(lines) + '\n'
    atomic_write(path, body)
    return len(lines)
