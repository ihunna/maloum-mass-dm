from app_configs import creators_file,configs_folder,universal_files
from utils import Utils
from configs import *
import io, threading, socketio, asyncio, traceback
from urllib.parse import urlparse
from curl_cffi.requests import AsyncSession
from curl_cffi.requests.exceptions import RequestException

Lock = threading.Lock()

def _mitmweb_enabled():
    # Temporary mitmweb bypass: mitmproxy's cert fails normal TLS verify.
    # Set MITMWEB=0 in .env to restore certificate verification.
    return os.getenv('MITMWEB', '1').strip().lower() not in ('0', 'false', 'no')


def _tls_impersonate():
    # Python's ssl/httpx cannot reproduce mitmproxy's ClientHello. curl_cffi can.
    # chrome_android matches the Android Chrome headers already sent to Maloum.
    return os.getenv('TLS_IMPERSONATE', 'chrome_android').strip() or 'chrome_android'


def _cookies_as_dict(cookies):
    if not cookies:
        return {}
    if hasattr(cookies, 'jar'):
        return {cookie.name: cookie.value for cookie in cookies.jar}
    if hasattr(cookies, 'items'):
        return dict(cookies.items())
    return dict(cookies)


DEFAULT_TIMEOUT = 120


class NetworkError(Exception):
    """Retryable transport failure (timeout, proxy, TLS, reset)."""


def _redact_proxy(proxy):
    if not isinstance(proxy, str) or not proxy:
        return proxy
    parsed = urlparse(proxy)
    if not parsed.password:
        return proxy
    host = parsed.hostname or ''
    port = f':{parsed.port}' if parsed.port else ''
    user = parsed.username or ''
    return f'{parsed.scheme}://{user}:***@{host}{port}'


def _timeout_seconds(timeout):
    if isinstance(timeout, tuple):
        return sum(float(part) for part in timeout)
    if timeout is None:
        return float(DEFAULT_TIMEOUT)
    return float(timeout)


def _format_network_error(error, method=None, url=None, proxy=None, timeout=None):
    raw = str(error).splitlines()[0].strip()
    lower = raw.lower()
    if 'curl: (28)' in raw or 'timed out' in lower:
        waited = f' after {_timeout_seconds(timeout):.0f}s' if timeout is not None else ''
        reason = f'Request timed out{waited}'
    elif 'curl: (7)' in raw:
        reason = 'Could not connect'
    elif 'curl: (56)' in raw:
        reason = 'Connection reset'
    elif 'curl: (35)' in raw:
        reason = 'TLS handshake failed'
    else:
        reason = raw[:180]

    details = []
    if method and url:
        details.append(f'{method} {url}')
    if proxy:
        details.append(f'proxy {_redact_proxy(proxy)}')
    if details:
        return f'{reason} ({", ".join(details)})'
    return reason


async def _http_failure(response, action):
    body = (await response.text() or '').strip()
    snippet = ' '.join(body.split())[:240] or 'empty body'
    if snippet.lstrip().startswith('<') or 'Just a moment' in snippet or 'cf-mitigated' in response.headers:
        return f'{action} blocked by Cloudflare (HTTP {response.status})'
    return f'{action} failed (HTTP {response.status}): {snippet}'


def _is_retryable_error(result):
    if isinstance(result, NetworkError):
        return True
    if not isinstance(result, str):
        return False
    text = result.lower()
    return any(token in text for token in (
        'timed out', 'could not connect', 'network error', 'connection reset',
        'tls handshake', 'cloudflare', 'challenge', 'try another proxy',
        'curl: (28)', 'curl: (7)', 'curl: (56)', 'curl: (35)',
    ))


class _Headers(dict):
    """Case-insensitive headers, matching aiohttp's CIMultiDict usage."""

    @staticmethod
    def _norm(key):
        return str(key).lower()

    def __init__(self, data=None):
        super().__init__()
        if data:
            self.update(data)

    def update(self, other=None, **kwargs):
        if other:
            items = other.items() if hasattr(other, 'items') else other
            for key, value in items:
                self[key] = value
        for key, value in kwargs.items():
            self[key] = value
        return None

    def __setitem__(self, key, value):
        super().__setitem__(self._norm(key), value)

    def __getitem__(self, key):
        return super().__getitem__(self._norm(key))

    def __delitem__(self, key):
        super().__delitem__(self._norm(key))

    def __contains__(self, key):
        return super().__contains__(self._norm(key))

    def get(self, key, default=None):
        return super().get(self._norm(key), default)

    def pop(self, key, *args):
        return super().pop(self._norm(key), *args)


class _CookieJar:
    def __init__(self):
        self._pending = {}
        self._client = None

    def bind(self, client):
        self._client = client
        if self._pending:
            client.cookies.update(self._pending)
            self._pending.clear()

    def update_cookies(self, cookies):
        if not cookies:
            return
        data = dict(cookies)
        if self._client is not None:
            self._client.cookies.update(data)
        else:
            self._pending.update(data)

    def filter_cookies(self, url):
        matched = dict(self._pending)
        if self._client is None:
            return matched
        cookies = getattr(self._client, 'cookies', None)
        if hasattr(cookies, 'jar'):
            host = (urlparse(url).hostname or '').lower()
            for cookie in cookies.jar:
                domain = (cookie.domain or '').lstrip('.').lower()
                if not domain or not host or host == domain or host.endswith('.' + domain):
                    matched[cookie.name] = cookie.value
            return matched
        matched.update(_cookies_as_dict(cookies))
        return matched

    def snapshot(self):
        cookies = dict(self._pending)
        if self._client is not None:
            cookies.update(_cookies_as_dict(getattr(self._client, 'cookies', None)))
        return cookies


_CURL_HTTP_VERSIONS = {
    1: 'HTTP/1.0',
    2: 'HTTP/1.1',
    3: 'HTTP/2',
    4: 'HTTP/2',
    5: 'HTTP/2',
    30: 'HTTP/3',
}


class _HttpResponse:
    def __init__(self, response):
        self._response = response
        self.status = response.status_code
        self.headers = response.headers
        version = getattr(response, 'http_version', None)
        self.http_version = _CURL_HTTP_VERSIONS.get(version, version)

    @property
    def ok(self):
        is_success = getattr(self._response, 'is_success', None)
        if is_success is not None:
            return is_success
        return 200 <= self.status < 300

    async def text(self):
        text = self._response.text
        if asyncio.iscoroutine(text):
            return await text
        return text

    async def json(self):
        data = self._response.json()
        if asyncio.iscoroutine(data):
            return await data
        return data

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        close = getattr(self._response, 'aclose', None) or getattr(self._response, 'close', None)
        if not close:
            return
        result = close()
        if asyncio.iscoroutine(result):
            await result


class _RequestContext:
    def __init__(self, session, method, url, kwargs):
        self._session = session
        self._method = method
        self._url = url
        self._kwargs = kwargs
        self._response = None

    async def __aenter__(self):
        self._response = await self._session._request(self._method, self._url, **self._kwargs)
        return self._response

    async def __aexit__(self, exc_type, exc, tb):
        if self._response is not None:
            return await self._response.__aexit__(exc_type, exc, tb)


class _HttpSession:
    """curl_cffi session with browser TLS/HTTP2 fingerprints, aiohttp-style API."""

    def __init__(self, headers=None):
        self.headers = _Headers(headers or {})
        self.cookie_jar = _CookieJar()
        self._client = None
        self._proxy = None
        self._lock = asyncio.Lock()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.close()

    @staticmethod
    def _normalize_proxy(proxy):
        if isinstance(proxy, dict):
            return proxy.get('http') or proxy.get('https')
        return proxy

    async def _ensure_client(self, proxy=None):
        proxy = self._normalize_proxy(proxy)
        async with self._lock:
            if self._client is not None and (proxy is None or proxy == self._proxy):
                return
            cookies = self.cookie_jar.snapshot()
            if self._client is not None:
                await self._client.close()
            if proxy is not None:
                self._proxy = proxy
            self._client = AsyncSession(
                impersonate=_tls_impersonate(),
                proxy=self._proxy,
                verify=not _mitmweb_enabled(),
                allow_redirects=True,
                cookies=cookies,
                timeout=DEFAULT_TIMEOUT,
            )
            self.cookie_jar.bind(self._client)

    async def _request(self, method, url, **kwargs):
        proxy = kwargs.pop('proxy', None)
        timeout = kwargs.pop('timeout', DEFAULT_TIMEOUT)
        await self._ensure_client(proxy)
        used_proxy = proxy or self._proxy
        try:
            response = await self._client.request(
                method,
                url,
                headers=dict(self.headers),
                timeout=timeout,
                **kwargs,
            )
        except RequestException as error:
            raise NetworkError(_format_network_error(
                error, method, url, used_proxy, timeout
            )) from error
        except OSError as error:
            raise NetworkError(_format_network_error(
                error, method, url, used_proxy, timeout
            )) from error
        return _HttpResponse(response)

    def get(self, url, **kwargs):
        return _RequestContext(self, 'GET', url, kwargs)

    def post(self, url, **kwargs):
        return _RequestContext(self, 'POST', url, kwargs)

    def patch(self, url, **kwargs):
        return _RequestContext(self, 'PATCH', url, kwargs)

    async def close(self):
        if self._client is not None:
            await self._client.close()
            self._client = None


def _http_session(**kwargs):
    return _HttpSession(headers=kwargs.get('headers'))

# Define a custom exception
class Cancelled(Exception):
    """Custom exception for specific error handling."""
    pass

class ChatClient:
    def __init__(self, ws_url, auth_token, proxies, timeout=30):
        session = requests.Session()
        session.proxies = Utils.format_proxy(proxies)
        session.verify = False

        self.sio = socketio.Client(
            http_session=session
        )
        
        self.ws_url = ws_url
        self.auth_token = auth_token
        self.timeout = timeout

        self.result = None
        self.temp_ack = None
        self._timer = None

        # Handlers
        self.sio.on("connect", self._on_connect, namespace="/chat")
        self.sio.on("receive_message", self._on_receive, namespace="/chat")
        self.sio.on("message", self._on_any_message, namespace="/chat")   # catch raw JSON error packets
        self.sio.on("error", self._on_error, namespace="/chat")
        self.sio.on("connect_error", self._on_connect_error, namespace="/chat")
        self.sio.on("disconnect", self._on_disconnect, namespace="/chat")

    def _on_connect(self):
        Utils.write_log("✅ Connected. Checking authentication...")
        self.sio.emit("authenticate", "ack", namespace="/chat", callback=self._on_auth)

    def _on_auth(self, resp):
        Utils.write_log(f"🔑 Auth response: { resp}")
        if self._has_error(resp):
            self._fail_and_disconnect(resp, reason="Auth error (callback)")
            return

        optimistic_id = str(uuid.uuid4())
        payload = {
            "chat": self.pending_chat,
            "content": self.pending_content,
            "optimisticMessageId": optimistic_id,
        }

        Utils.write_log("📤 Sending message...")
        self.sio.emit("send_message", payload, namespace="/chat", callback=self._on_send)

    def _on_send(self, resp):
        Utils.write_log(f"📩 Send ACK: {resp}")

        if self._has_error(resp):
            self._fail_and_disconnect(resp, reason="Send error")
            return
        self.temp_ack = resp

        # Consider message sent successfully, set result and disconnect
        self.result = (True, {"ack": self.temp_ack})
        self.sio.disconnect()

    def _on_receive(self, data):
        Utils.write_log("📨 Final receive_message: waiting for message confirmation")
        self._cancel_timeout()
        if self._has_error(data):
            self._fail_and_disconnect(data, reason="Receive error")
        else:
            self.result = (True, {"ack": self.temp_ack, "receive": data})
            self.sio.disconnect()

    def _on_any_message(self, data):
        """Catch stray messages like Unauthorized JSON strings"""
        Utils.write_log(f"📡 Raw message received: {data}")
        parsed = None
        if isinstance(data, str):
            try:
                parsed = json.loads(data)
            except Exception:
                return
        elif isinstance(data, dict):
            parsed = data

        if parsed and self._has_error(parsed):
            self._fail_and_disconnect(parsed, reason="Auth error (raw msg)")

    def _on_error(self, data):
        Utils.write_log(f"⚠️ Socket error: { data}")
        self._fail_and_disconnect(data, reason="Socket error")

    def _on_connect_error(self, data):
        Utils.write_log(f"⚠️ Connect error: { data}")
        self._fail_and_disconnect(data, reason="Connect error")

    def _on_disconnect(self):
        Utils.write_log("🔌 Disconnected.")

    def send_message(self, chat_id, content):
        """One-shot flow: connect → authenticate → send → receive → disconnect"""
        self.pending_chat = chat_id
        self.pending_content = content
        self.result = None
        self.temp_ack = None

        try:
            self.sio.connect(
                self.ws_url,
                transports=["websocket"],
                namespaces=["/chat"],
                auth={"authorization": f"Bearer {self.auth_token}"}
            )
            self.sio.wait()
        except Exception as e:
            return False, str(e)

        return self.result

    def _start_timeout(self):
        self._cancel_timeout()
        self._timer = threading.Timer(self.timeout, self._on_timeout)
        self._timer.start()

    def _cancel_timeout(self):
        if self._timer:
            self._timer.cancel()
            self._timer = None

    def _on_timeout(self):
        Utils.write_log(f"⏳ Timeout: No receive_message after {self.timeout}s")
        self.result = (False, "timeout")
        self.sio.disconnect()

    def _fail_and_disconnect(self, resp, reason="Error"):
        Utils.write_log(f"⛔ {reason}, disconnecting...")
        self.result = (False, resp)
        self._cancel_timeout()
        self.sio.disconnect()

    @staticmethod
    def _has_error(resp):
        """Treat any response containing 'error' or statusCode != 200 as failure"""
        if resp is None:
            return True
        if isinstance(resp, dict):
            if resp.get("statusCode") and resp.get("statusCode") != 200:
                return True
            if resp.get("error"):
                return True
        if isinstance(resp, str) and "Unauthorized" in resp:
            return True
        return False



class Creator:
    def __init__(self):
        self.proxies = Utils.load_proxies()
        self.headers = {
            'accept': 'application/json',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/json',
            'origin': 'https://app.maloum.com',
            'priority': 'u=1, i',
            'referer': 'https://app.maloum.com/',
            'sec-ch-ua': '"Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"',
            'sec-ch-ua-mobile': '?1',
            'sec-ch-ua-platform': '"Android"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': 'Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Mobile Safari/537.36',
            'x-timezone': 'Africa/Lagos',
        }
        self._message_cache = {}  # Cache for recent recipients per creator
        self.scraped_cache = []
        self.categories = Utils.load_categories()

    @staticmethod
    def _trace_headers():
        trace_id = os.urandom(16).hex()
        original = f'00-{trace_id}-{os.urandom(8).hex()}-01'
        current = f'00-{trace_id}-{os.urandom(8).hex()}-01'
        return {
            'traceparent': current,
            'x-original-traceparent': original,
        }

    @staticmethod
    async def _response_json(response):
        text = await response.text()
        if text.lstrip().startswith('<') or 'Just a moment' in text or 'cf-mitigated' in response.headers:
            raise Exception(
                'Maloum blocked this request with a Cloudflare challenge. '
                'The proxy or IP is being challenged; try another proxy.'
            )
        try:
            return json.loads(text)
        except json.JSONDecodeError as error:
            raise Exception(
                f'Invalid JSON from Maloum ({response.status}): {text[:180]}'
            ) from error
        
    def format_proxy(self,proxies):
        return proxies['http']

    def generate_sensor_data(self, type='x-auth-resource'):
        if type == 'x-auth-resource':
            return ''.join(random.choices(string.ascii_letters.upper() + string.digits + string.ascii_letters, k=10))
        elif type == 'dsc_r':
            return ''.join(random.choices(string.ascii_letters.upper() + string.digits + string.ascii_letters, k=8))

    def _reuse_ip(self, account, config=None):
        if config and config.get('proxy_flush'):
            return False
        data = account.get('data') or account
        return data.get('reuse_ip', account.get('reuse_ip', True))

    def apply_proxy_flush(self, accounts):
        updated = 0
        for account in accounts:
            data = account.get('data') or {}
            if not data.get('proxies'):
                continue
            success, msg = self.update(account, {'reuse_ip': False})
            if success:
                account['data']['reuse_ip'] = False
                updated += 1
            else:
                Utils.write_log(msg)
        return updated

    async def update_media_id(self, post_id, creator, creator_id):
        async with _http_session(headers=creator.get('data', {}).get('headers')) as session:
            session.headers.update({'user-agent': Utils.generate_user_agent('android', 1)})
            proxies = Utils.format_proxy(random.choice(self.proxies)) if not creator.get('reuse_ip') else creator.get('proxies')
            try:
                async with session.get(
                    f'https://api.maloum.com/posts/{post_id}',
                    proxy=proxies,
                    timeout=90
                ) as response:
                    if not response.ok:
                        raise Exception(await _http_failure(response, f'Fetch media ID for {post_id}'))
                    media = (await response.json()).get('media', [])
                    if not media:
                        raise Exception(f'No media ID found for {post_id}')
                    media = media[0]
                    media_id = media.get("uploadId")

                    success, msg = self.update(creator, {'media': media, 'post_id': post_id})
                    if not success:
                        raise Exception(f'Error updating creator {creator_id} with media ID {media_id}: {msg}')
                    return True, f'Successfully saved media ID {media_id} for creator {creator_id}'
            except Exception as e:
                return False, f'Error saving media ID {post_id} for creator {creator_id}: {str(e)}'

    async def scrape_users(self, scraper, admin, task_id, count=50, limit=50, offset=0, last_activity=7):
        try:
            if not isinstance(scraper, dict) or not scraper.get('id'):
                return False, f'Scraper is not logged in: {scraper}'

            success, task_status = Utils.check_task_status(task_id)
            if not success:
                raise Exception(task_status)
            if task_status['status'].lower() in ['cancelled', 'canceled']:
                return False, 'Task canceled'
            
            client_msg = {'msg': f'Scraping users by {scraper["id"]}', 'status': 'success', 'type': 'message'}
            success, msg = Utils.update_client(client_msg)

            auth_headers = scraper.get('headers') or {}
            headers = {
                'accept': 'application/json',
                'accept-language': 'en-US,en;q=0.9',
                'authorization': auth_headers.get('authorization'),
                'origin': 'https://app.maloum.com',
                'priority': 'u=1, i',
                'referer': 'https://app.maloum.com/',
                'sec-ch-ua': '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
                'sec-ch-ua-mobile': '?1',
                'sec-ch-ua-platform': '"Android"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-site',
                'user-agent': Utils.generate_user_agent('android', 1),
            }

            async with _http_session(headers=headers) as session:
                # session.cookie_jar.update_cookies(scraper.get('cookies'))
                proxies = scraper.get('proxies', Utils.format_proxy(random.choice(self.proxies))) \
                    if scraper.get('reuse_ip', True) else Utils.format_proxy(random.choice(self.proxies))

                #Set random preferences
                cat = random.choice(self.categories)
                json_data = {
                    'categories': [
                        cat.get('_id'),
                    ],
                    'sexualPreferences': [
                            '141400000000000000002000',
                        ],
                    }
                async with session.patch(
                    'https://api.maloum.com/users/current/preferences',
                    json=json_data,
                    proxy=proxies,
                    timeout=120
                ) as response:
                    if not response.ok:
                        raise Exception(await _http_failure(response, 'Set preferences'))
                    client_msg = {'msg': f'Category preferences set to {cat.get('name')}', 'status': 'success', 'type': 'message'}
                    Utils.update_client(client_msg)

                    Utils.write_log(f"--- Category preferences set to {cat.get('name')} ---")

                async with session.get(
                    'https://api.maloum.com/content/discovery',
                    params={'limit': f'30', 'dsc_r': self.generate_sensor_data('dsc_r')},
                    proxy=proxies,
                    timeout=90
                ) as response:
                    if not response.ok:
                        raise Exception(await _http_failure(response, 'Get discovery posts'))
                    posts = (await response.json()).get('data', [])

                total_creators = 0
                total_existing = 0
                valid_users = []
                candidate_users = []
                BATCH_SIZE = 100
                lock = asyncio.Lock()

                async def flush_candidates():
                    nonlocal candidate_users, valid_users, total_creators, total_existing
                    if not candidate_users:
                        return

                    while candidate_users:
                        batch = candidate_users[:BATCH_SIZE]
                        candidate_users = candidate_users[BATCH_SIZE:]

                        batch_ids = [u["_id"] for u in batch]

                        success, existing_ids = Utils.get_existing_user_ids(batch_ids, admin=admin)
                        if not success:
                            Utils.write_log(f"DB check failed: {existing_ids}")
                            return

                        new_users = [u for u in batch if u["_id"] not in existing_ids]

                        if new_users:
                            success, msg = Utils.add_users(new_users, admin=admin, task_id=task_id)
                            if not success:Utils.write_log(f"Insert failed: {msg}")
                            else:valid_users.extend(new_users)

                        if existing_ids:
                            client_msg = {'msg': f'Skipped {len(existing_ids)} users because they already exist in the database', 'status': 'success', 'type': 'message'}
                            Utils.update_client(client_msg)
                            total_existing += len(existing_ids)


                semaphore = asyncio.Semaphore(3)  # allow max 3 requests at once
                async def process_post(post):
                    try:
                        nonlocal total_creators, total_existing, candidate_users, valid_users
                        # # add an initial random delay so not all tasks fire at once
                        # await asyncio.sleep(random.uniform(1, 5))

                        success, task_status = Utils.check_task_status(task_id)
                        if not success:
                            raise Exception(task_status)
                        if task_status['status'].lower() in ['cancelled', 'canceled']:
                            return False, 'Task canceled'

                        post_id, comment_count, _next = post.get('_id'), post.get('commentCount'), None
                        if not post_id or comment_count is None:
                            raise Exception('Post ID or Comment count missing from post dict')

                        creators = []

                        while comment_count > 0:
                            success, task_status = Utils.check_task_status(task_id)
                            if not success:
                                raise Exception(task_status)
                            if task_status['status'].lower() in ['cancelled', 'canceled']:
                                return False, 'Task canceled'

                            params = {'limit': '50'}
                            if _next is not None:
                                params['next'] = _next

                            # remove headers safely
                            for key in ['x-client-info', 'x-supabase-api-version', 'apikey']:
                                session.headers.pop(key, None)

                            session.headers.update({
                                'user-agent': Utils.generate_user_agent('android', 1)
                            })

                            # prevent too many concurrent requests
                            async with semaphore:
                                # random delay before hitting the endpoint
                                await asyncio.sleep(random.uniform(3, 5))

                                async with session.get(
                                    f'https://api.maloum.com/posts/{post_id}/comments',
                                    params=params,
                                    proxy=proxies,
                                    timeout=120
                                ) as response:
                                    if not response.ok:
                                        raise Exception(await _http_failure(response, f'Get comments for post {post_id}'))

                                    data = await response.json()
                                    comments, _next = data.get('data', []), data.get('next')
                                    comment_count -= len(comments)

                                    creators = [c for c in comments if c.get('user', {}).get('isCreator', False)]
                                    
                                    for comment in comments:
                                        u = comment.get('user')
                                        if not u:
                                            continue

                                        user = {
                                            "_id": u["_id"],
                                            "username": u["username"],
                                            "commented_at": comment.get("createdAt")
                                        }

                                        if not u.get('isCreator', True):
                                            async with lock:
                                                # if len(valid_users) >= count:
                                                #     await flush_candidates()
                                                #     return True, f'{post.get("commentCount")} processed for post {post_id}'

                                                candidate_users.append(user)
                                                # if len(candidate_users) >= BATCH_SIZE:
                                                #     await flush_candidates()
                                    if not _next:break

                        await flush_candidates()

                        if len(creators) > 0:
                            client_msg = {'msg': f"Skipped {len(creators)} creators on post {post_id}", 'status': 'success', 'type': 'message'}
                            Utils.update_client(client_msg)
                            total_creators += len(creators)

                        return True, f'{post.get("commentCount")} processed for post {post_id}'

                    except Exception as error:
                        if error == '':
                            tb = traceback.format_exc()
                            return False, f'{post.get("_id")} failed to process comments | {error.__class__.__name__}: {str(error)}\n{tb}'
                        return False, f'{post.get("_id")} failed to process comments | {str(error)}'

                tasks = [process_post(post) for post in posts]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        Utils.write_log(result)
                    elif isinstance(result, tuple) and not result[0]:
                        Utils.write_log(result[1])

                if not valid_users and (total_creators > 0 or total_existing > 0):
                    raise Exception(f'No users found | Because {total_creators} creators were skipped and {total_existing} existing users already exist in the database')
                if not valid_users:
                    return False, f'No valid users found for {scraper["id"]}'
                return True, f'Scraped {len(valid_users)} users by {scraper["id"]}'

        except Exception as e:
            return False, f'Error scraping users: {e}'


    async def send_messages(self, admin, task_id, creator, scrapers, config, max_actions):
        try:
            success, task_status = Utils.check_task_status(task_id)
            if not success:
                raise Exception(task_status)
            if task_status['status'].lower() in ['cancelled', 'canceled']:
                return False, 'Task canceled'

            if not creator.get('data', {}):
                raise Exception('creator data not available')

            email = creator['data']['details']['user']['email']
            password = creator['data']['details']['user']['password']

            success, _creator = await self.login(
                admin, email, password, reuse_ip=self._reuse_ip(creator, config), task_id=task_id
            )
            if not success:
                raise Exception(_creator)
            creator_data = _creator

            auth_token = creator_data['details']['user']['accessToken']
            creator_name = creator_data['details']['user']['username']
            creator_id = creator_data['details']['user']['_id']
            creator_internal_id = creator['id']

            caption = config.get('caption', '')
            caption_source = config.get('caption_source', 'creator')
            has_media = config.get('has_media', False)
            media = creator_data.get('media', {})
            media_id = media.get('uploadId')
            is_paid = False if config.get('cost_type', 'free') == 'free' else True
            price = config.get('price', 0)

            if caption_source == 'creator':
                captions_file = os.path.join(configs_folder, creator_internal_id, 'captions.txt')
                if not os.path.isfile(captions_file):
                    raise Exception(f'Captions file does not exist for {creator_name}')
                with open(captions_file, 'r', encoding='utf-8') as f:
                    captions = [line.strip() for line in f.readlines()]
                    if not captions:
                        raise ValueError('Captions cannot be empty')

            # NOTE: scraping is handled elsewhere now; this function only pulls from DB
            offset = creator_data.get('message_offset', 0)
            client_msg = {'msg': f'Fetching users from DB (unmessaged by {creator_name}) offset {offset}', 'status': 'success', 'type': 'message'}
            success, msg = Utils.update_client(client_msg)

            Utils.write_log(f"--- Fetching users from DB (unmessaged by {creator_name}) offset {offset} ---")

            async with _http_session() as session:
                session.headers.update(creator_data.get('headers'))
                session.headers.update(self._trace_headers())
                session.cookie_jar.update_cookies(creator_data.get('cookies'))
                proxies = creator_data.get('proxies', Utils.format_proxy(random.choice(self.proxies))) if creator_data.get('reuse_ip', True) else Utils.format_proxy(random.choice(self.proxies))

                limit = max_actions
                users, found_users = [], 0

                success, msg, total_users = Utils.get_users(admin)
                if not success:raise Exception(msg)

                if offset >= total_users:offset = 0

                # 🔁 Pull only users NOT previously messaged by this creator (from DB)
                while found_users < max_actions:
                    # expects you have Utils.get_unmessaged_users(creator_id, limit, offset) implemented
                    success, new_users = Utils.get_unmessaged_users(creator_internal_id, limit=limit, offset=offset)
                    if not success:raise Exception(new_users)
                    if not new_users:break

                    users.extend(new_users)
                    found_users += len(new_users)
                    offset += limit

                success_messages = 0
                backfilled_messages = 0

                random.shuffle(users)

                if len(users) == 0:
                    return False, f'No unmessaged users found for {creator_name} at offset {offset}'

                for user in users:
                    try:
                        # Check cancel
                        success, task_status = Utils.check_task_status(task_id)
                        if not success:
                            raise Exception(task_status)
                        if task_status['status'].lower() in ['cancelled', 'canceled']:
                            return False, 'Task canceled'

                        # Handle id field naming (`_id` vs `id`)
                        recipient_id = user.get('_id') or user.get('id')
                        if not recipient_id:
                            Utils.write_log(f"--- Skipping user without id: {user} ---")
                            continue
                        username = user.get('username', 'unknown')

                        already_ok, already = Utils.has_message(creator_id=creator_internal_id, recipient_id=recipient_id)
                        if already_ok and already:
                            Utils.write_log(f'--- Skipping {username}; already messaged by {creator_name} ---')
                            continue

                        # Create new chat
                        async with session.post(
                            'https://api.maloum.com/chats',
                            json={'member2': recipient_id},
                            proxy=proxies,
                            timeout=90
                        ) as response:
                            if not response.ok:
                                err_text = await _http_failure(response, f'Create chat for {username}')
                                Utils.write_log(f"--- {err_text} ---")
                                if response.status == 404:
                                    client_msg = {'msg': f"This user {username} no longer exists, skipping it", 'status': 'success', 'type': 'message'}
                                    success, msg = Utils.update_user(recipient_id, 'inactive')
                                    if not success:Utils.write_log(f"--- Failed to mark user {username} as inactive: {msg} ---")
                                else:
                                    client_msg = {'msg': err_text, 'status': 'error', 'type': 'message'}
                                success, msg = Utils.update_client(client_msg)
                                continue
                            
                            chat_data = await response.json()
                            if chat_data.get('chatPartner',{}).get('isCreator', True):
                                client_msg = {'msg': f"Skipping chat with {username} because it is a creator", 'status': 'error', 'type': 'message'}
                                success, msg = Utils.update_client(client_msg)
                                Utils.write_log(f"--- Skipping user {username} who is a creator ---")
                                
                                success,msg = Utils.delete_user(recipient_id)
                                if not success:
                                    Utils.write_log(f"--- Failed to delete user {username} who is a creator: {msg} ---")
                                
                                else:
                                    client_msg = {'msg': f"Deleted {username} because it is a creator", 'status': 'error', 'type': 'message'}
                                    success, msg = Utils.update_client(client_msg)
                                    Utils.write_log(f"--- Deleted user {username} who is a creator ---")
                                continue
                            
                            chat_id = (chat_data).get('_id')
                            if not chat_id:
                                client_msg = {'msg': f"--- No chat ID found for user {recipient_id} ---", 'status': 'error', 'type': 'message'}
                                success, msg = Utils.update_client(client_msg)
                                Utils.write_log(f"--- No chat ID found for user {recipient_id} ---")
                                continue

                        already_ok, already = Utils.has_message(message_id=chat_id)
                        if already_ok and already:
                            Utils.write_log(f'--- Skipping {username}; chat {chat_id} already recorded ---')
                            continue

                        # Check for existing messages in the chat
                        async with session.get(
                            f'https://api.maloum.com/chats/{chat_id}/messages',
                            params={'limit': 50},   # fetch enough to find the creator's last msg
                            proxy=proxies,
                            timeout=90
                        ) as response:
                            if not response.ok:
                                Utils.write_log(f"--- {await _http_failure(response, f'Check messages for chat {chat_id}')} ---")
                                continue
                            
                            data = await response.json()
                            messages = data.get('data', [])

                            if messages:
                                # Find the last message where the sender is the creator
                                creator_messages = [m for m in messages if m.get('senderId') == creator_id]
                                if creator_messages:
                                    last_msg = creator_messages[-1]  # last one authored by creator

                                    msg_text = last_msg.get('content', {}).get('text', '')
                                    has_media = last_msg.get('content', {}).get('type') != 'text'

                                    success, add_msg_resp = Utils.add_message(
                                        chat_id,
                                        admin,
                                        creator_internal_id,
                                        creator_name,
                                        recipient_id,
                                        username,
                                        has_media,
                                        f'https://app.maloum.com/chat/{chat_id}',
                                        'sent',   # always "sent" since creator authored it
                                        msg_text,
                                        price,
                                        task_id
                                    )

                                    if success:
                                        client_msg = {
                                            'msg': f'Backfilled last sent message for user @{username} by {creator_name}',
                                            'status': 'success',
                                            'type': 'message'
                                        }
                                        Utils.update_client(client_msg)
                                        Utils.write_log(f"--- Backfilled last sent message for user @{username} by {creator_name} ---")
                                        backfilled_messages += 1
                                        continue
                                    else:
                                        Utils.write_log(f"--- Failed to backfill last sent message for {username}: {add_msg_resp} ---")
                                        continue
                                
                                else:
                                    client_msg = {'msg': f"Skipping chat with {username} because it already has a message", 'status': 'error', 'type': 'message'}
                                    success, msg = Utils.update_client(client_msg)
                                    continue

                        # Prepare message
                        chosen_caption = random.choice(captions) if caption_source == 'creator' else caption

                        content = {
                            'type': 'text',
                            'text': chosen_caption
                        }

                        if has_media and media_id:
                            media_info = {
                                "mediaId": media.get("uploadId"),
                                "type": media.get("type"),
                                "width": media.get("width"),
                                "height": media.get("height")
                            }
                            content = {
                                "type": "media" if not (is_paid and price > 0) else "chat_product",
                                "media": [media_info],
                                "text": chosen_caption
                            }
                            if is_paid and price > 0:
                                content["priceNet"] = price
                            
                        json_data = {
                            'content': content,
                            'optimisticMessageId': str(uuid.uuid4())
                        }

                        # Random delay to avoid rate-limiting
                        await asyncio.sleep(random.randint(2, 5))

                        # Send the message
                        async with session.post(
                            f'https://api.maloum.com/chats/{chat_id}/messages',
                            json=json_data,
                            proxy=proxies,
                            timeout=90
                        ) as response:
                            if not response.ok:
                                Utils.write_log(f"--- {await _http_failure(response, f'Send message for chat {chat_id}')} ---")
                                continue
                            
                        # Add message to db via Utils.add_message
                        success, add_msg_resp = Utils.add_message(
                            chat_id,
                            admin,
                            creator_internal_id,
                            creator_name,
                            recipient_id,
                            username,
                            has_media,
                            f'https://app.maloum.com/chat/{chat_id}',
                            'sent',
                            chosen_caption,
                            price,
                            task_id
                        )
                        if not success:
                            Utils.write_log(f'Error adding message to database for {username} by {creator_name}: {add_msg_resp}')
                            client_msg = {'msg': f'Error adding message to database for {username} by {creator_name}: {add_msg_resp}', 'status': 'error', 'type': 'message'}
                            Utils.update_client(client_msg)
                            continue
                        Utils.write_log(f'=== Successfully sent a message to {username} by {creator_name} ===')
                        
                        client_msg = {'msg': f'Successfully sent a message to {username} by {creator_name}', 'status': 'success', 'type': 'message'}
                        success, update_msg = Utils.update_client(client_msg)
                        if not success:
                            Utils.write_log(update_msg)

                        success_messages += 1

                        if success_messages >= max_actions:
                            break

                    except Exception as e:
                        Utils.write_log(str(e))
                        client_msg = {'msg': f'Failed to message user {username}: {e}', 'status': 'error', 'type': 'message'}
                        success, _ = Utils.update_client(client_msg)
                        continue
            
            # Update creator's message offset
            success, msg = self.update(creator, {'message_offset': offset})
            if not success:Utils.write_log(msg)
            
            if success_messages > 0:
                return True, f'Successfully sent messages to {success_messages} users by {creator_name}'
            if backfilled_messages > 0:
                return True, f'No new messages sent by {creator_name}; recorded {backfilled_messages} existing chats'
            return False, f'{creator_name} could not send any messages to users'

        except Exception as e:
            return False, f'Error sending messages to users for {creator.get("id")}: {str(e)}'


    async def login(self, admin, email, password, reuse_ip=True, task_id=None, category='creators'):
        attempts = 3
        last_error = None
        for attempt in range(1, attempts + 1):
            success, result = await self._try_login(
                admin, email, password, reuse_ip=reuse_ip, task_id=task_id, category=category
            )
            if success:
                return success, result
            last_error = result
            if not _is_retryable_error(result) or attempt == attempts:
                return False, result
            Utils.write_log(f'Retrying login for {email} ({attempt}/{attempts}): {result}')
            await asyncio.sleep(min(2 * attempt, 5))
        return False, last_error

    async def _try_login(self, admin, email, password, reuse_ip=True, task_id=None, category='creators'):
        async with _http_session() as session:
            try:
                success, task_status = Utils.check_task_status(task_id) if task_id else (False, 'No task ID provided')
                if not success:
                    raise Exception(task_status)
                if task_status.get('status', '').lower() in ['cancelled', 'canceled']:
                    return False, 'Task canceled'

                success, user = Utils.check_creator(email, admin)
                if not success:raise Exception(user)

                creator_id = user.get('id',None)
                user_data = user.get('data', {})
                new_user = creator_id is None

                if reuse_ip and 'proxies' in user_data:
                    proxies = user_data['proxies']
                else:proxies = Utils.format_proxy(random.choice(self.proxies))
                proxies = Utils.format_proxy(random.choice(self.proxies))

                print(f'--- Logging in {email} with proxy {proxies} ---')

                if not new_user:
                    session.headers.update(user_data.get('headers', {}))
                    session.headers.update(self._trace_headers())
                    refresh_token = user_data['details']['user']['refreshToken']
                    token = user_data['details']['user']['accessToken']
                    if category=='creators':Utils.write_log(f'token before refresh {token}')
                    del session.headers['authorization']

                    #refresh token
                    async with session.post(
                        'https://srswgacczfgjttwdpuia.supabase.co/auth/v1/token',
                        params={'grant_type': 'refresh_token'},
                        json={'refresh_token': refresh_token},
                        proxy=proxies,
                        timeout=120
                    ) as response:
                        if not response.ok:
                            Utils.write_log(
                                f'could not refresh access token for {email}: '
                                f'{await _http_failure(response, "token refresh")}; moving on with proper login'
                            )
                        
                        else:
                            login_data = await response.json()
                            token, refresh_token = login_data['access_token'], login_data['refresh_token']
                            if category == 'creators':Utils.write_log(f'token after refresh {token}')
                            
                            session.headers.update({
                                'authorization': f'Bearer {token}'
                            })

                            user_data['details']['user'].update({
                                'accessToken':token,
                                'refreshToken':refresh_token,
                                'last_login':login_data.get('user',{}).get('last_sign_in_at')
                            })
                            user_data.update({
                                'headers':dict(session.headers),
                                'proxies':proxies
                            })

                            user_data['cookies'] = {
                                key: str(value) for key, value in session.cookie_jar.filter_cookies('https://api.maloum.com').items()
                            }

                            success, msg = Utils.update_creator(creator_id, email, user_data)
                            if not success:raise Exception(msg)
                            await session.close()
                            user_data['id'] = creator_id
                            return True, user_data


                session.headers.update(self.headers)
                session.headers.update(self._trace_headers())
                session.headers.update({'user-agent': Utils.generate_user_agent('android', 1)})
                
                async with session.post(
                    'https://api.maloum.com/user-management/login',
                    json={'usernameOrEmail': email, 'password': password},
                    proxy=proxies,
                    timeout=120
                ) as response:
                    if response.status == 401:
                        return False, 'Credentials not correct'
                    if not response.ok:
                        user_data['status'] = 'Offline'
                        return False, await _http_failure(response, f'Login for {email}')

                    login_data = await self._response_json(response)
                    token, refresh_token = login_data['accessToken'], login_data['refreshToken']
                    session.headers.update({
                        'apikey': 'sb_publishable_4zljSqmEuxGuqPttJAK_kg_XzInyyJ9',
                        'authorization': f'Bearer {token}',
                        'x-client-info': 'supabase-js-web/2.103.2',
                        'x-supabase-api-version': '2024-01-01',
                    })

                    async with session.get(
                        'https://srswgacczfgjttwdpuia.supabase.co/auth/v1/user',
                        proxy=proxies,
                        timeout=120
                    ) as response:
                        if not response.ok:
                            raise Exception(await _http_failure(response, 'Fetch account credentials'))
                        login_state = await response.json()

                    async with session.get(
                        'https://api.maloum.com/users/current',
                        proxy=proxies,
                        timeout=120
                    ) as response:
                        if not response.ok:
                            raise Exception(await _http_failure(response, 'Fetch current user'))
                        account = await response.json()

                    profile = {}
                    if category == 'creators':
                        async with session.get(
                            f'https://api.maloum.com/users/{account["username"]}/profile',
                            proxy=proxies,
                            timeout=120
                        ) as response:
                            if not response.ok:
                                raise Exception(await _http_failure(response, 'Fetch user profile'))
                            profile = await response.json()

                    data = {
                        'user': {
                            'last_login': login_state.get('last_sign_in_at'),
                            'status': login_state.get('role'),
                            **account,
                            **profile,
                            **login_data
                        }
                    }

                    user_data['status'] = 'Online' if data['user'].get('status') == 'authenticated' else 'Offline'
                    user_data['details'] = data
                    user_data['details']['user']['password'] = password
                    user_data['headers'] = dict(session.headers)
                    user_data['cookies'] = {
                        key: str(value) for key, value in session.cookie_jar.filter_cookies('https://api.maloum.com').items()
                    }
                    user_data['proxies'] = proxies
                    user_data['reuse_ip'] = reuse_ip

                    if new_user:
                        creator_id = str(uuid.uuid4()).upper()[:8]
                        success, msg = Utils.add_creator(creator_id, email, user_data, admin, category=category, task_id=task_id)
                        os.makedirs(os.path.join(configs_folder, creator_id, 'images'), exist_ok=True)
                        os.makedirs(os.path.join(configs_folder, creator_id, 'videos'), exist_ok=True)
                        with open(os.path.join(configs_folder, creator_id, 'captions.txt'), 'w') as file:
                            file.write("")
                    else:
                        success, msg = Utils.update_creator(creator_id, email, user_data)
                        if not success:
                            raise Exception(msg)

                    user_data['id'] = creator_id
                    await session.close()
                    return True, user_data

            except NetworkError as e:
                Utils.write_log(f'Login network error on {email}: {e}')
                return False, f'Login failed for {email}: {e}'
            except Exception as e:
                tb = traceback.format_exc()
                Utils.write_log(f'Error in login {e} on {email}\n{tb}')
                return False, f'Error in login on {email}: {e}'
            
    def update(self,user:dict,data:dict):
        try:
            user_email,user_id,user = user['email'],user['id'],user['data']
            for key,value in data.items():
                user[key] = value
            success,msg = Utils.update_creator(user_id,user_email,user)
            if not success:raise Exception(msg)
            return True,user
        except Exception as error:
            return False, error
    

class _MALOUM:
    def __init__(self):
        self.proxies = Utils.load_proxies()
        self.headers = {
            'authority': 'rest.4based.com',
            'accept': 'application/json',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/json',
            'origin': 'https://4based.com',
            'referer': 'https://4based.com/',
            'sec-ch-ua': '"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"',
            'sec-ch-ua-mobile': '?1',
            'sec-ch-ua-platform': '"Android"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site'
        }

    async def add_creators(self, admin, task, creators, category):
        task_status, task_msg, completed, fails = 'running', f'Started logging in creators for {task["id"]}', 0, 0
        task_id = task['id']
        try:
            Utils.write_log(f'=== Add {category} started for {task["id"]} ===')

            async def login_creator(creator):
                success, current_task = Utils.check_task_status(task_id)
                if not success:
                    raise Exception(current_task)
                if current_task['status'].lower() in ['cancelled', 'canceled']:
                    return False, 'Task canceled'
                ok, msg = await Creator().login(admin, creator['email'], creator['password'], task_id=task_id, category=category)
                if not ok:
                    return False, f"{creator.get('email')}: {msg}"
                return True, msg

            tasks = [login_creator(creator) for creator in creators]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for item in results:
                if isinstance(item, Exception):
                    success, result = False, str(item)
                elif isinstance(item, (tuple, list)) and len(item) == 2:
                    success, result = item
                else:
                    success, result = False, str(item)

                if success:
                    completed += 1
                    task_msg = f'{completed} {category} added so far on task:{task_id}'
                    Utils.push_task_update(task, 'running', task_msg, client_status='success')
                elif result == 'Task canceled':
                    task_status = 'canceled'
                    task_msg = f'{result} task:{task_id}'
                    Utils.push_task_update(task, task_status, task_msg)
                    break
                else:
                    fails += 1
                    task_msg = str(result)
                    Utils.push_task_update(task, 'running', task_msg, client_status='error')

                Utils.write_log(task_msg)

        except Exception as e:
            Utils.write_log(e)
            task_status = 'failed'
            task_msg = f'Error adding creators on {task_id}: {e}'
            Utils.push_task_update(task, task_status, task_msg)

        finally:
            if task_status == 'canceled':
                pass
            elif completed == len(creators) and len(creators) > 0:
                task_status = 'success'
                task_msg = f'{task_id} successful'
            elif fails > 0:
                task_status = 'failed'
            else:
                task_status = 'completed'
                task_msg = f'{completed} items successful task:{task_id}'

            Utils.push_task_update(task, task_status, task_msg)

    async def start_messaging(self, task, max_actions=20):
        task_status, task_msg = 'failed', f'Started messaging for {task["id"]}'
        try:
            admin = task['admin']
            task_id = task['id']
            config = task['config']
            selected_creators = config.get('selected_creators', [])
            time_between = config.get('time_between', 60)
            time_message = {
                '60': '1 minute', '120': '2 minutes', '180': '3 minutes', '300': '5 minutes',
                '600': '10 minutes', '1200': '20 minutes', '1800': '30 minutes', '3600': '1 hour',
                '7200': '2 hours', '10800': '3 hours', '21600': '6 hours', '86400': '24 hours'
            }

            success, creators, total_creators = Utils.get_creators(admin=admin, limit=100, selected_creators=selected_creators)
            if not success:
                raise Exception(creators)

            len_creators = len(creators)
            if len_creators < total_creators:
                for i in range(total_creators - len_creators):
                    offset = len_creators + i
                    success, msg, total_creators = Utils.get_creators(admin=admin, limit=100, offset=offset, selected_creators=selected_creators)
                    if not success:
                        raise Exception(msg)
                    creators.extend(msg)

            success, scrapers, total_scrapers = Utils.get_creators(admin=admin, limit=100, category='users')
            if not success:raise Exception(scrapers)

            len_scrapers = len(scrapers)
            if len_scrapers < total_scrapers:
                for i in range(total_scrapers - len_scrapers):
                    offset = len_scrapers + i
                    success, msg, total_scrapers = Utils.get_creators(admin=admin, limit=100, offset=offset, category='users')
                    if not success:
                        raise Exception(msg)
                    scrapers.extend(msg)

            if config.get('proxy_flush'):
                flushed = Creator().apply_proxy_flush(creators) + Creator().apply_proxy_flush(scrapers)
                Utils.write_log(f'Proxy flush enabled: reuse_ip disabled for {flushed} accounts with stored proxies')
                client_msg = {'msg': f'Proxy flush enabled: reuse_ip disabled for {flushed} accounts with stored proxies', 'status': 'success', 'type': 'message'}
                Utils.update_client(client_msg)

            Utils.write_log(f'=== Messaging started for {task_id} ===')

            while True:
                success, task_status = Utils.check_task_status(task_id)
                if not success:
                    raise Exception(task_status)
                if task_status['status'].lower() in ['cancelled', 'canceled']:
                    break

                tasks = [
                    Creator().send_messages(admin, task_id, creator, scrapers, config, max_actions)
                    for creator in creators
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for item in results:
                    if isinstance(item, Exception):
                        success, result = False, str(item)
                    elif isinstance(item, (tuple, list)) and len(item) == 2:
                        success, result = item
                    else:
                        success, result = False, str(item)

                    if not success:
                        client_msg = {'msg': f'Error messaging users on {task_id}: {result}', 'status': 'error', 'type': 'message'}
                        success, msg = Utils.update_client(client_msg)
                    else:
                        client_msg = {'msg': f'Success messaging users on {task_id}: {result}', 'status': 'success', 'type': 'message'}
                        success, msg = Utils.update_client(client_msg)

                    Utils.write_log(f'=== {result} ===')

                wait_message = f'Waiting for {time_message[str(time_between)]} before sending another batch of messages'
                Utils.write_log(wait_message)

                client_msg = {'msg': wait_message, 'status': 'success', 'type': 'message'}
                success, msg = Utils.update_client(client_msg)
                
                sleep_time = 10
                for _ in range(int(time_between / sleep_time)):
                    print(f'Sleeping for {sleep_time} seconds')
                    success, task_status = Utils.check_task_status(task_id)
                    if not success:raise Exception(task_status)
                    if task_status['status'].lower() in ['cancelled', 'canceled']:
                        raise Cancelled(task_status)
                    await asyncio.sleep(sleep_time)


        except Cancelled as error:
            task_status = task_status['status'] if isinstance(task_status,dict) else task_status
            if  task_status.lower() in ['cancelled', 'canceled']:
                client_msg = {'msg': f'Task | {task_id} has been cancelled', 'status': 'error', 'type': 'message'}
                success, msg = Utils.update_client(client_msg)
                if not success:
                    Utils.write_log(msg)
                Utils.write_log(f'Task | {task_id} was stopped')
            else:
                Utils.write_log(f'Task | {task_id} finished operation')

        except Exception as e:
            Utils.write_log(e)
            task_status = 'failed'
            task_msg = f'Error in messaging | {task_id}: {e}'
            client_msg = {'msg': f'Error in messaging | {task_id}: {e}', 'status': 'error', 'type': 'message'}
            success, msg = Utils.update_client(client_msg)
            if not success:
                Utils.write_log(msg)

            success, msg = Utils.update_task(task_id, {'status': task_status, 'message': task_msg})
            task_data = task
            task_data.update({'updated': str(datetime.now()), 'status': task_status})
            success, msg = Utils.update_client({'task': task_data, 'type': 'task'})
            if not success:
                Utils.write_log(msg)

        finally:
            task_status = task_status['status'] if isinstance(task_status,dict) else task_status
            if  task_status.lower() in ['cancelled', 'canceled']:
                client_msg = {'msg': f'Task | {task_id} has been cancelled', 'status': 'error', 'type': 'message'}
                success, msg = Utils.update_client(client_msg)
                if not success:
                    Utils.write_log(msg)
                Utils.write_log(f'Task | {task_id} was stopped')
            else:
                Utils.write_log(f'Task | {task_id} finished operation')


    async def start_scraping(self, task):
        task_status, task_msg = 'failed', f'Started scraping for {task["id"]}'
        try:
            admin = task['admin']
            task_id = task['id']
            config = task['config']
            time_between = config.get('time_between', 60)
            time_message = {
                '60': '1 minute', '120': '2 minutes', '180': '3 minutes', '300': '5 minutes',
                '600': '10 minutes', '1200': '20 minutes', '1800': '30 minutes', '3600': '1 hour',
                '7200': '2 hours', '10800': '3 hours', '21600': '6 hours', '86400': '24 hours'
            }

            success, scrapers, total_scrapers = Utils.get_creators(admin=admin, limit=100, category='users')
            if not success:raise Exception(scrapers)
            if total_scrapers < 1: raise Exception('Scrapers can not be empty')

            len_scrapers = len(scrapers)
            if len_scrapers < total_scrapers:
                for i in range(total_scrapers - len_scrapers):
                    offset = len_scrapers + i
                    success, msg, total_scrapers = Utils.get_creators(admin=admin, limit=100, offset=offset, category='users')
                    if not success: raise Exception(msg)
                    scrapers.extend(msg)

            if config.get('proxy_flush'):
                flushed = Creator().apply_proxy_flush(scrapers)
                Utils.write_log(f'Proxy flush enabled: reuse_ip disabled for {flushed} accounts with stored proxies')
                client_msg = {'msg': f'Proxy flush enabled: reuse_ip disabled for {flushed} accounts with stored proxies', 'status': 'success', 'type': 'message'}
                Utils.update_client(client_msg)

            Utils.write_log(f'=== Scraping started for {task_id} ===')

            offset, i = 0, 0
            count = config.get('max_actions',10)
            last_activity = config.get('last_activity',7)

            while True:
                success, task_status = Utils.check_task_status(task_id)
                if not success:
                    raise Exception(task_status)
                if task_status['status'].lower() in ['cancelled', 'canceled']:
                    break
                
                target_scraper = scrapers[i]
                email = target_scraper.get('email') or target_scraper.get('id')
                success, scraper = await Creator().login(
                    admin, 
                    target_scraper['email'], 
                    target_scraper['data']['details']['user']['password'],
                    reuse_ip=Creator()._reuse_ip(target_scraper, config), 
                    task_id=task_id, 
                    category='users'
                )

                if not success:
                    result = scraper if isinstance(scraper, str) else f'Login failed for {email}'
                    client_msg = {'msg': f'Error scraping users on {task_id}: {result}', 'status': 'error', 'type': 'message'}
                    Utils.update_client(client_msg)
                    Utils.write_log(f'=== {result} ===')
                    i = i + 1 if i < len(scrapers) - 1 else 0
                    await asyncio.sleep(5)
                    continue

                success, result = await Creator().scrape_users(
                    scraper, 
                    admin, 
                    task_id, 
                    count = count,
                    last_activity = last_activity,
                    offset = offset)

                if not success:
                    client_msg = {'msg': f'Error scraping users on {task_id}: {result}', 'status': 'error', 'type': 'message'}
                    success, msg = Utils.update_client(client_msg)

                else:
                    client_msg = {'msg': result, 'status': 'success', 'type': 'message'}
                    success, msg = Utils.update_client(client_msg)

                Utils.write_log(f'=== {result} ===')


                wait_message = f'Waiting for {time_message[str(time_between)]} before scraping another batch of users'
                Utils.write_log(wait_message)
                client_msg = {'msg': wait_message, 'status': 'success', 'type': 'message'}
                success, msg = Utils.update_client(client_msg)
                
                sleep_time = 10
                for _ in range(int(time_between / sleep_time)):
                    print(f'Sleeping for {sleep_time} seconds')
                    success, task_status = Utils.check_task_status(task_id)
                    if not success:raise Exception(task_status)
                    if task_status['status'].lower() in ['cancelled', 'canceled']:
                        raise Cancelled(task_status)
                    await asyncio.sleep(sleep_time)

                offset += count if offset < 400 else 0
                i = i + 1 if i < len(scrapers) - 1 else 0


        except Cancelled as error:
            task_status = task_status['status'] if isinstance(task_status,dict) else task_status
            if  task_status.lower() in ['cancelled', 'canceled']:
                client_msg = {'msg': f'Task | {task_id} has been cancelled', 'status': 'error', 'type': 'message'}
                success, msg = Utils.update_client(client_msg)
                if not success:
                    Utils.write_log(msg)
                Utils.write_log(f'Task | {task_id} was stopped')
            else:
                Utils.write_log(f'Task | {task_id} finished operation')

        except Exception as e:
            Utils.write_log(e)
            task_status = 'failed'
            task_msg = f'Error in scraping | {task_id}: {e}'
            client_msg = {'msg': f'Error in scraping | {task_id}: {e}', 'status': 'error', 'type': 'message'}
            success, msg = Utils.update_client(client_msg)
            if not success:
                Utils.write_log(msg)

            success, msg = Utils.update_task(task_id, {'status': task_status, 'message': task_msg})
            task_data = task
            task_data.update({'updated': str(datetime.now()), 'status': task_status})
            success, msg = Utils.update_client({'task': task_data, 'type': 'task'})
            if not success:
                Utils.write_log(msg)

        finally:
            task_status = task_status['status'] if isinstance(task_status,dict) else task_status
            if  task_status.lower() in ['cancelled', 'canceled']:
                client_msg = {'msg': f'Task | {task_id} has been cancelled', 'status': 'error', 'type': 'message'}
                success, msg = Utils.update_client(client_msg)
                if not success:
                    Utils.write_log(msg)
                Utils.write_log(f'Task | {task_id} was stopped')
            else:
                Utils.write_log(f'Task | {task_id} finished operation')
