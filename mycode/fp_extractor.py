import hashlib
import re
import mmh3
from network_request import NetworkRequest


class FingerprintExtractor:

    def __init__(self, db_path="fp_db.json"):
        self.db_path = db_path

    def extract_http_header_features(self, http_headers):
        """
        提取HTTP响应头特征（返回小写字典）
        """
        features = {}
        for header, value in http_headers.items():
            features[header.lower()] = value.lower()
        return features

    def _get_headers_text(self, http_headers):
        """
        将HTTP响应头拼接为文本字符串，格式：key1: value1\nkey2: value2 ...
        所有内容转换为小写，便于后续关键词匹配
        """
        lines = []
        for k, v in http_headers.items():
            lines.append(f"{k.lower()}: {v.lower()}")
        return "\n".join(lines)

    def extract_html_tag_features(self, html_content):
        """
        提取HTML内容（仅转换为小写，截断已在请求层控制）
        """
        if not html_content:
            return ""
        return html_content.lower()

    def extract_title_feature(self, html_content):
        """
        提取<title>标签内容
        """
        if not html_content:
            return ""
        match = re.search(r"<title>(.*?)</title>", html_content, re.IGNORECASE | re.S)
        if match:
            return match.group(1).lower()
        return ""

    def extract_favicon_feature(self, url, nr):
        """
        提取favicon的mmh3哈希值（32位有符号整数，返回字符串形式）
        """
        try:
            favicon_binary = nr.get_favicon(url)
            if favicon_binary:
                hash_int = mmh3.hash(favicon_binary)
                return str(hash_int)
        except Exception:
            pass
        return ""

    # 完整的 get_all_features 方法（直接替换你现有 fp_extractor.py 中的同名方法即可）
    import re

    def get_all_features(self, url, nr, full_html=False):
        result = {
            "status": False,
            "msg": "",
            "features": {}
        }

        try:
            resp = nr.send_request(url, scan_full_html=full_html)
            if not resp["status"]:
                result["msg"] = resp["msg"]
                return result

            html_content = resp["html_content"]
            http_header = resp["http_header"]

            # 提取title
            title = ""
            if "<title>" in html_content and "</title>" in html_content:
                start = html_content.find("<title>") + 7
                end = html_content.find("</title>")
                title = html_content[start:end].strip()

            # 构造header文本
            header_text = ""
            for k, v in http_header.items():
                header_text += f"{k}: {v}\n"

            # 新增：提取版本信息
            version = self._extract_version(html_content, http_header)

            # 填充特征（新增version字段）
            result["features"] = {
                "html_tag": html_content,
                "title": title,
                "http_header": http_header,
                "header_text": header_text,
                "version": version  # 新增
            }
            result["status"] = True
            result["msg"] = "特征提取成功"

            return result
        except Exception as e:
            result["msg"] = str(e)
            return result

    def _extract_version(self, html_content, http_header):
        """
        内部辅助方法：从HTML和HTTP头中提取版本信息
        """
        version_candidates = []
        
        # 1. 从HTTP头提取（Server、X-Powered-By等）
        for header in ["Server", "X-Powered-By", "X-Generator"]:
            if header in http_header:
                val = http_header[header]
                # 简单正则提取版本号（数字.数字.数字格式）
                ver_match = re.search(r'(\d+\.\d+(\.\d+)?)', val)
                if ver_match:
                    version_candidates.append(ver_match.group(1))
        
        # 2. 从HTML meta标签提取（generator、version等）
        meta_patterns = [
            r'<meta[^>]*name="generator"[^>]*content="([^"]*)"',
            r'<meta[^>]*name="version"[^>]*content="([^"]*)"',
            r'<meta[^>]*property="og:site_name"[^>]*content="([^"]*)"'
        ]
        for pattern in meta_patterns:
            match = re.search(pattern, html_content, re.IGNORECASE)
            if match:
                ver_match = re.search(r'(\d+\.\d+(\.\d+)?)', match.group(1))
                if ver_match:
                    version_candidates.append(ver_match.group(1))
        
        # 3. 从HTML注释中提取
        comment_pattern = r'<!--(.*?)-->'
        for comment in re.findall(comment_pattern, html_content, re.DOTALL):
            ver_match = re.search(r'(\d+\.\d+(\.\d+)?)', comment)
            if ver_match:
                version_candidates.append(ver_match.group(1))
        
        # 返回第一个找到的版本，若无则返回空字符串
        return version_candidates[0] if version_candidates else ""