import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from typing import Dict


async def perform_login(session: aiohttp.ClientSession, login_url: str, username: str, password: str,
                        user_field: str = 'username', pass_field: str = 'password') -> Dict[str, str]:
    async with session.get(login_url) as resp:
        text = await resp.text()
    soup = BeautifulSoup(text, 'html.parser')
    form = soup.find('form')
    data = {}
    if form:
        for inp in form.find_all('input'):
            if inp.get('name') and inp.get('value'):
                data[inp['name']] = inp['value']
    data[user_field] = username
    data[pass_field] = password
    action = form.get('action') if form else login_url
    login_endpoint = action if action.startswith('http') else urljoin(login_url, action)
    async with session.post(login_endpoint, data=data) as resp:
        await resp.text()
    return session.cookie_jar.filter_cookies(login_url)
