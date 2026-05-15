import mmh3
import base64
import re
import difflib  # 新增：用于字符串相似度计算

class FingerprintMatcher:
    def __init__(self, fp_data=None):
        self.fingerprints = []
        if fp_data:
            self.load_fingerprints(fp_data)

    def load_fingerprints(self, fp_data):
        self.fingerprints = fp_data.get("fingerprint", fp_data.get("fingerprints", []))

    def _calc_favicon_mmh3(self, favicon_binary):
        if not favicon_binary or len(favicon_binary) == 0:
            return ""
        try:
            favicon_base64 = base64.encodebytes(favicon_binary)
            hash_int = mmh3.hash(favicon_base64)
            return str(hash_int)
        except Exception:
            return ""

    def _normalize_text(self, text):
        """内部辅助：标准化文本，去除干扰字符"""
        # 去除多余空白、换行符，统一转为小写
        return re.sub(r'\s+', ' ', text).strip().lower()

    def _fuzzy_keyword_match(self, target, keyword, min_similarity=0.85):
        """
        内部辅助：模糊关键词匹配
        策略：
        1. 先尝试精确包含
        2. 若失败，尝试去除标点后的包含
        3. 若仍失败，计算字符串相似度
        """
        target_norm = self._normalize_text(target)
        keyword_norm = self._normalize_text(keyword)

        # 1. 精确包含（优先级最高）
        if keyword_norm in target_norm:
            return True, 1.0

        # 2. 宽松包含：去除所有标点符号后再试
        target_no_punc = re.sub(r'[^\w\s]', '', target_norm)
        keyword_no_punc = re.sub(r'[^\w\s]', '', keyword_norm)
        if keyword_no_punc in target_no_punc:
            return True, 0.95

        # 3. 相似度匹配（针对关键词被截断或微改的情况）
        # 只有当目标文本长度大于关键词一半时才进行相似度计算，避免误判
        if len(target_norm) >= len(keyword_norm) * 0.5:
            similarity = difflib.SequenceMatcher(None, keyword_norm, target_norm).ratio()
            if similarity >= min_similarity:
                return True, similarity

        return False, 0.0

    def match(self, response):
        results = []
        body = response.get("body", "").lower()
        title = response.get("title", "").lower()
        headers = {k.lower(): str(v).lower() for k, v in response.get("headers", {}).items()}
        header_text = response.get("header_text", "").lower()
        favicon_binary = response.get("favicon", b"")
        favicon_hash = self._calc_favicon_mmh3(favicon_binary)
        extracted_version = response.get("version", "")

        for fp in self.fingerprints:
            cms_name = fp.get("cms", "未知组件")
            match_method = fp.get("method", "keyword")
            match_location = fp.get("location", "body")
            rule_keywords = fp.get("keyword", [])
            version_rule = fp.get("version_rule", "")
            
            if isinstance(rule_keywords, str):
                rule_keywords = [rule_keywords]
            # 不再强制转小写，因为 _fuzzy_keyword_match 内部会处理
            # rule_keywords = [k.lower() for k in rule_keywords]

            confidence = 0
            match_detail = []
            match_success = False
            matched_version = "未知"

            # 1. 增强版关键词匹配（核心修改）
            if match_method == "keyword":
                threshold = fp.get("threshold", 0.5) 
                target_text = ""
                base_confidence = 80
                
                if match_location == "body":
                    target_text = body
                elif match_location == "title":
                    target_text = title
                    base_confidence = 90
                elif match_location == "header":
                    target_text = header_text
                    base_confidence = 85

                if target_text and len(rule_keywords) > 0:
                    hit_count = 0
                    max_similarity = 0.0
                    hit_keywords = []

                    for keyword in rule_keywords:
                        is_hit, similarity = self._fuzzy_keyword_match(target_text, keyword)
                        if is_hit:
                            hit_count += 1
                            max_similarity = max(max_similarity, similarity)
                            hit_keywords.append(keyword)

                    hit_ratio = hit_count / len(rule_keywords)

                    if hit_ratio >= threshold:
                        # 结合命中率和相似度动态计算置信度
                        final_confidence = int(base_confidence * hit_ratio * max_similarity)
                        confidence += final_confidence
                        match_detail.append(f"关键词命中: {hit_count}/{len(rule_keywords)} (最高相似度:{max_similarity:.2f}) - {','.join(hit_keywords)}")
                        match_success = True

            # 2. 正则匹配（保持原样，以备将来扩展）
            elif match_method == "regex":
                target_text = ""
                base_confidence = 88
                if match_location == "body":
                    target_text = body
                elif match_location == "title":
                    target_text = title
                elif match_location == "header":
                    target_text = header_text

                if target_text:
                    try:
                        for pattern in rule_keywords:
                            if re.search(pattern, target_text):
                                confidence += base_confidence
                                match_detail.append(f"正则匹配: {pattern}")
                                match_success = True
                                break
                    except re.error:
                        pass

            # 3. Favicon哈希匹配（保持不变）
            elif match_method == "faviconhash":
                if favicon_hash and favicon_hash in rule_keywords:
                    confidence += 95
                    match_detail.append(f"favicon哈希匹配: {favicon_hash}")
                    match_success = True

            # 4. 版本提取逻辑（保持不变）
            if match_success and confidence >= 60:
                if version_rule:
                    target_text = ""
                    if match_location == "body":
                        target_text = body
                    elif match_location == "title":
                        target_text = title
                    elif match_location == "header":
                        target_text = header_text
                    
                    if target_text:
                        try:
                            ver_match = re.search(version_rule, target_text)
                            if ver_match:
                                matched_version = ver_match.group(1)
                        except re.error:
                            pass
                
                if matched_version == "未知" and extracted_version:
                    matched_version = extracted_version

                results.append({
                    "name": cms_name,
                    "type": "CMS/应用组件",
                    "version": matched_version,
                    "match_dimension": f"{match_method}:{match_location}",
                    "confidence": min(confidence, 100),
                    "detail": match_detail
                })

        unique_results = {}
        for res in results:
            name = res["name"]
            if name not in unique_results or res["confidence"] > unique_results[name]["confidence"]:
                unique_results[name] = res

        return sorted(list(unique_results.values()), key=lambda x: x["confidence"], reverse=True)