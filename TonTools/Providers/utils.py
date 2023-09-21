import logging
import unicodedata
from base64 import b64decode
import aiohttp

import asyncio
from tonsdk.boc import Cell
from tonsdk.utils import Address, bytes_to_b64str, b64str_to_bytes

from ton.account import Account
from ton import TonlibClient
from ton.utils.cell import read_address

logger = logging.getLogger(__name__)


def is_hex(str):
    try:
        int(str, 16)
        return True
    except:
        return False


def process_jetton_data(data):
    if not len(Cell.one_from_boc(b64decode(data)).refs):
        url = Cell.one_from_boc(b64decode(data)).bits.get_top_upped_array().decode().split('\x01')[-1]
        return url
    else:
        symbol = Cell.one_from_boc(b64decode(data)).refs[0].refs[1].refs[0].refs[1].refs[0].bits.get_top_upped_array().decode().split('\x00')[-1]
        try:
            desc1 = unicodedata.normalize("NFKD", Cell.one_from_boc(b64decode(data)).refs[0].refs[1].refs[1].refs[0].refs[0].bits.get_top_upped_array().decode().split('\x00')[-1])  # Cell.one_from_boc(b64decode(data)).refs[0].refs[1].refs[1].refs[0].refs
        except (IndexError, TypeError, AttributeError):
            logger.warning("Unable to get desc1 from jetton. Set empty value")
            desc1 = ''
        try:
            desc2 = unicodedata.normalize("NFKD", Cell.one_from_boc(b64decode(data)).refs[0].refs[1].refs[1].refs[0].refs[0].refs[0].bits.get_top_upped_array().decode().split('\x00')[-1]) if len(Cell.one_from_boc(b64decode(data)).refs[0].refs[1].refs[1].refs[0].refs[0].refs) else ''
        except (IndexError, TypeError, AttributeError):
            logger.warning("Unable to get desc2 from jetton. Set empty value")
            desc2 = ''
        try:
            decimals = int(Cell.one_from_boc(b64decode(data)).refs[0].refs[1].refs[1].refs[1].refs[0].bits.get_top_upped_array().decode().split('\x00')[-1])
        except (IndexError, TypeError, AttributeError):
            logger.warning("Unable to get decimals from jetton. Set empty value")
            decimals = None
        try:
            name = Cell.one_from_boc(b64decode(data)).refs[0].refs[1].refs[0].refs[0].refs[0].bits.get_top_upped_array().decode().split('\x00')[-1]
        except (IndexError, TypeError, AttributeError):
            logger.warning("Unable to get name from jetton. Set empty value")
            name = ''
        try:
            image = Cell.one_from_boc(b64decode(data)).refs[0].refs[0].refs[0].bits.get_top_upped_array().decode().split('\x00')[-1]
        except (IndexError, TypeError, AttributeError):
            logger.warning("Unable to get image from jetton. Set empty value")
            image = ''
        data = {
            'name': name,
            'image': image,
            'symbol': symbol,
        }
        if any((desc1, desc2)):
            data['description'] = desc1 + desc2
        if decimals is not None:
            data['decimals'] = decimals

        return data


async def get(url: str):
    if 'ipfs' in url:
        url = 'https://ipfs.io/ipfs/' + url.split('ipfs://')[-1]
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            return await response.json(content_type=None)

markets_adresses = {
    '0:584ee61b2dff0837116d0fcb5078d93964bcbe9c05fd6a141b1bfca5d6a43e18': 'Getgems Sales',
    '0:a3935861f79daf59a13d6d182e1640210c02f98e3df18fda74b8f5ab141abf18': 'Getgems Sales',
    '0:eb2eaf97ea32993470127208218748758a88374ad2bbd739fc75c9ab3a3f233d': 'Disintar Marketplace',
    '0:1ecdb7672d5b0b4aaf2d9d5573687c7190aa6849804d9e7d7aef71975ac03e2e': 'TON Diamonds'
}
