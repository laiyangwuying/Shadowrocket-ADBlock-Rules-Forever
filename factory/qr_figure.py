# -*- coding: utf-8 -*-
"""构建 figure/*.png 订阅二维码（与 readme 规则地址一致）。"""

from __future__ import annotations

from pathlib import Path

import qrcode
import requests
from qrcode.constants import ERROR_CORRECT_M

from build_confs import CONFS_NAMES
from build_util import FACTORY_ROOT, log
from lazy_deploy import LAZY_FILES
from publish_urls import GUIDE_PNG_URL, pages_conf_url

REPO_ROOT = FACTORY_ROOT.parent
FIGURE_DIR = REPO_ROOT / 'figure'

QR_CONF_FILES = tuple(f'{name}.conf' for name in CONFS_NAMES) + LAZY_FILES


def _write_png(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_bytes(data)
    tmp.replace(path)


def _generate_qr_png(url: str, dest: Path) -> None:
    qr = qrcode.QRCode(
        version=None,
        error_correction=ERROR_CORRECT_M,
        box_size=8,
        border=2,
    )
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    dest.parent.mkdir(parents=True, exist_ok=True)
    img.save(dest)


def _ensure_guide_png() -> bool:
    guide = FIGURE_DIR / 'guide.png'
    if guide.is_file():
        return False
    r = requests.get(GUIDE_PNG_URL, timeout=30)
    r.raise_for_status()
    _write_png(guide, r.content)
    log('qr_figure: fetched guide.png from upstream')
    return True


def build() -> dict:
    written: list[str] = []
    for conf_file in QR_CONF_FILES:
        url = pages_conf_url(conf_file)
        png_name = f'{Path(conf_file).stem}.png'
        _generate_qr_png(url, FIGURE_DIR / png_name)
        written.append(png_name)

    guide_added = _ensure_guide_png()
    if guide_added:
        written.append('guide.png')

    log(f'qr_figure: wrote {len(written)} image(s) under figure/')
    return {'qrs': len(written)}


def main() -> int:
    build()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
