import requests
import random
import socket
import threading
from urllib.parse import urlparse, urljoin
from collections import OrderedDict
import time
from requests.adapters import HTTPAdapter

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False
    print("[!] 未安装tldextract，递归子域名探测功能受限，请执行：pip install tldextract")

TIMEOUT = 15
RETRY_COUNT = 2

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
]

COMMON_PORTS = [21, 22, 80, 443, 3306, 3389, 6379, 8080, 8443, 9000]
COMMON_SUBDOMAIN_PREFIXES = ["www", "api", "admin", "mail", "ftp", "test", "dev", "bbs", "web", "cdn", "static", "vpn", "portal", "manage", "blog", "shop"]


class URLPreprocessor:
    @staticmethod
    def complete_url(url):
        parsed = urlparse(url)
        if not parsed.scheme:
            return f"https://{url}", f"http://{url}"
        return url, None

    @staticmethod
    def parse_url(url):
        parsed = urlparse(url)
        return {
            "scheme": parsed.scheme,
            "domain": parsed.netloc.split(":")[0],
            "port": parsed.netloc.split(":")[1] if ":" in parsed.netloc else (443 if parsed.scheme == "https" else 80),
            "path": parsed.path,
            "full_url": parsed.geturl()
        }

    @staticmethod
    def deduplicate_urls(urls):
        return list(OrderedDict.fromkeys(urls))
    
    @staticmethod
    def get_root_domain(domain):
        if not HAS_TLDEXTRACT:
            parts = domain.split(".")
            if len(parts) >= 2:
                return ".".join(parts[-2:])
            return domain
        ext = tldextract.extract(domain)
        return f"{ext.domain}.{ext.suffix}"


class PortScanner:
    @staticmethod
    def scan(domain, ports=COMMON_PORTS, timeout=2):
        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((domain, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except Exception:
                continue
        return open_ports


class SubdomainDetector:
    def __init__(self):
        self.prefixes = COMMON_SUBDOMAIN_PREFIXES
        self._detected_domains = set()
        self._lock = threading.Lock()

    def _add_detected(self, domain):
        with self._lock:
            self._detected_domains.add(domain.lower())

    def _is_detected(self, domain):
        return domain.lower() in self._detected_domains

    def detect_single_level(self, parent_domain):
        alive_subdomains = []
        for prefix in self.prefixes:
            subdomain = f"{prefix}.{parent_domain}"
            if self._is_detected(subdomain):
                continue
            self._add_detected(subdomain)
            try:
                socket.gethostbyname(subdomain)
                alive_subdomains.append(subdomain)
            except socket.error:
                continue
        return alive_subdomains

    def recursive_detect(self, input_domain, max_level=2):
        self._detected_domains.clear()
        root_domain = URLPreprocessor.get_root_domain(input_domain)
        alive_domains = []
        current_level_domains = [root_domain]

        for current_level in range(1, max_level):
            next_level_domains = []
            for parent_domain in current_level_domains:
                level_alive = self.detect_single_level(parent_domain)
                alive_domains.extend(level_alive)
                next_level_domains.extend(level_alive)
            current_level_domains = next_level_domains
            if not current_level_domains:
                break

        return alive_domains

    @staticmethod
    def detect(domain, subdomains=COMMON_SUBDOMAIN_PREFIXES):
        found_subdomains = []
        for sub in subdomains:
            subdomain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                found_subdomains.append(subdomain)
            except socket.error:
                continue
        return found_subdomains


class NetworkRequest:
    def __init__(self, preferred_client="requests", timeout=TIMEOUT):
        """
        初始化网络请求器（支持自动切换客户端）
        :param preferred_client: 优先使用的客户端，可选 "requests" 或 "httpx"
        :param timeout: 请求超时时间（秒）
        """
        self.preferred_client = preferred_client.lower()
        self.timeout = timeout
        self.proxies = None
        self.ua_pool = UA_POOL

        # 始终初始化requests客户端（保证基础可用性）
        self.session = requests.Session()
        adapter = HTTPAdapter(pool_connections=100, pool_maxsize=100)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()

        # 仅当安装了httpx时初始化httpx客户端
        self.httpx_client = None
        if HAS_HTTPX:
            self.httpx_client = httpx.Client(verify=False, timeout=self.timeout)

        self.preprocessor = URLPreprocessor()
        self.port_scanner = PortScanner()
        self.subdomain_detector = SubdomainDetector()

    def set_proxy(self, proxies):
        self.proxies = proxies

    def _get_random_ua(self):
        return random.choice(self.ua_pool)

    def _auto_switch_get(self, url, headers=None, follow_redirects=True):
        """
        核心方法：自动切换客户端的GET请求
        优先使用指定的客户端，失败后自动切换到另一个
        每个客户端最多重试 RETRY_COUNT 次
        """
        if headers is None:
            headers = {"User-Agent": self._get_random_ua()}

        # 构建客户端尝试顺序
        client_order = []
        if self.preferred_client == "requests":
            client_order.append(("requests", self.session))
            if self.httpx_client is not None:
                client_order.append(("httpx", self.httpx_client))
        else:  # 优先httpx
            if self.httpx_client is not None:
                client_order.append(("httpx", self.httpx_client))
            client_order.append(("requests", self.session))

        last_error = ""
        # 按顺序尝试每个客户端
        for client_name, client in client_order:
            for retry in range(RETRY_COUNT + 1):
                try:
                    if client_name == "requests":
                        response = client.get(
                            url,
                            headers=headers,
                            timeout=self.timeout,
                            allow_redirects=follow_redirects,
                            proxies=self.proxies,
                            verify=False
                        )
                    else:  # httpx
                        response = client.get(
                            url,
                            headers=headers,
                            timeout=self.timeout,
                            follow_redirects=follow_redirects,
                            proxies=self.proxies
                        )

                    # 成功状态码判断
                    if response.status_code in [200, 301, 302, 307, 308]:
                        return response, None
                    else:
                        last_error = f"{client_name} 状态码错误: {response.status_code}"
                except Exception as e:
                    last_error = f"{client_name} 请求异常: {str(e)[:50]}"

                # 重试前等待1秒
                if retry < RETRY_COUNT:
                    time.sleep(1)

        # 所有客户端都失败
        return None, last_error

    def send_request(self, url, scan_full_html: bool = False):
        if not url:
            return {"status": False, "msg": "URL为空"}

        main_url, backup_url = self.preprocessor.complete_url(url)
        response_data = {
            "status": False,
            "http_header": {},
            "html_content": "",
            "msg": ""
        }

        # 先尝试主URL
        response, error = self._auto_switch_get(main_url)
        if response is not None:
            html = response.text
            response_data["status"] = True
            response_data["http_header"] = dict(response.headers)
            response_data["html_content"] = html if scan_full_html else html[:100000]
            response_data["msg"] = f"请求成功（{response.url}，状态码：{response.status_code}）"
            return response_data

        # 主URL失败，尝试备份URL（http/https切换）
        if backup_url:
            response, error = self._auto_switch_get(backup_url)
            if response is not None:
                html = response.text
                response_data["status"] = True
                response_data["http_header"] = dict(response.headers)
                response_data["html_content"] = html if scan_full_html else html[:100000]
                response_data["msg"] = f"请求成功（{response.url}，状态码：{response.status_code}）"
                return response_data

        # 所有尝试都失败
        response_data["msg"] = f"所有客户端都失败: {error}"
        return response_data

    def get_favicon_hash(self, url):
        if not url:
            return ""
        favicon_url = urljoin(url, "/favicon.ico")
        try:
            response, error = self._auto_switch_get(favicon_url)
            if response is not None and len(response.content) > 0:
                import mmh3
                import base64
                favicon = base64.encodebytes(response.content)
                return str(mmh3.hash(favicon))
        except Exception:
            pass
        return ""

    def get_favicon(self, url):
        from urllib.parse import urljoin
        if not url:
            return b""
        favicon_url = urljoin(url, "/favicon.ico")
        try:
            response, error = self._auto_switch_get(favicon_url)
            if response is not None and len(response.content) > 0:
                return response.content
        except Exception:
            pass
        return b""

    def close(self):
        # 关闭所有客户端
        if hasattr(self, 'session') and self.session is not None:
            self.session.close()
        if hasattr(self, 'httpx_client') and self.httpx_client is not None:
            self.httpx_client.close()