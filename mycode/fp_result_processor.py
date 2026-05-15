import json
import csv
import os
import sqlite3
from datetime import datetime
from fp_matcher import FingerprintMatcher
from fp_extractor import FingerprintExtractor
from network_request import NetworkRequest



class ScanHistoryDB:
    """扫描历史数据库管理类"""
    def __init__(self, db_path="scan_history.db"):
        self.db_path = db_path
        self.max_size_gb = 2.0
        self._init_db()

    def _init_db(self):
        """初始化数据库表"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 创建扫描任务表（记录每次扫描的批次）
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_name TEXT,
                start_time TEXT,
                end_time TEXT,
                total_targets INTEGER,
                success_count INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # 创建扫描结果表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER,
                url TEXT NOT NULL,
                url_type TEXT,
                parent_url TEXT,
                scan_time TEXT,
                status_code TEXT,
                is_success INTEGER,
                match_count INTEGER,
                open_ports TEXT,
                raw_result_json TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (task_id) REFERENCES scan_tasks(id)
            )
        ''')
        
        # 创建指纹匹配详情表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS fingerprint_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                result_id INTEGER,
                software_name TEXT,
                software_type TEXT,
                version TEXT,
                match_dimension TEXT,
                confidence INTEGER,
                detail TEXT,
                FOREIGN KEY (result_id) REFERENCES scan_results(id)
            )
        ''')
        
        # 创建索引
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_result_url ON scan_results(url)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_result_time ON scan_results(created_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_fp_name ON fingerprint_matches(software_name)')
        
        conn.commit()
        conn.close()

    def _check_and_cleanup(self):
        """检查数据库大小，超过2G则删除最早的记录"""
        if not os.path.exists(self.db_path):
            return
        
        size_gb = os.path.getsize(self.db_path) / (1024 * 1024 * 1024)
        if size_gb < self.max_size_gb:
            return

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 删除最早的 20% 任务
        cursor.execute('SELECT id FROM scan_tasks ORDER BY created_at ASC LIMIT (SELECT COUNT(*) FROM scan_tasks) / 5')
        old_task_ids = [row[0] for row in cursor.fetchall()]
        
        if old_task_ids:
            placeholders = ','.join('?' for _ in old_task_ids)
            cursor.execute(f'DELETE FROM fingerprint_matches WHERE result_id IN (SELECT id FROM scan_results WHERE task_id IN ({placeholders}))', old_task_ids)
            cursor.execute(f'DELETE FROM scan_results WHERE task_id IN ({placeholders})', old_task_ids)
            cursor.execute(f'DELETE FROM scan_tasks WHERE id IN ({placeholders})', old_task_ids)
            print(f"[*] 数据库清理：删除了 {len(old_task_ids)} 个旧任务记录")
        
        conn.commit()
        conn.close()

    def save_scan_task(self, task_name, start_time, total_targets):
        """创建一个新的扫描任务"""
        self._check_and_cleanup()
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO scan_tasks (task_name, start_time, total_targets) VALUES (?, ?, ?)',
            (task_name, start_time, total_targets)
        )
        task_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return task_id

    def update_scan_task(self, task_id, end_time, success_count):
        """更新扫描任务完成状态"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE scan_tasks SET end_time=?, success_count=? WHERE id=?',
            (end_time, success_count, task_id)
        )
        conn.commit()
        conn.close()

    def save_scan_result(self, task_id, result_data):
        """保存单个URL的扫描结果"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        url = result_data.get("url", "")
        url_type = result_data.get("url_type", "main")
        parent_url = result_data.get("parent_url", "")
        scan_time = result_data.get("scan_time", "")
        is_success = 1 if result_data.get("status") else 0
        request_info = result_data.get("request_info", {})
        status_code = request_info.get("status_code", "Failed")
        
        match_result = result_data.get("match_result", {})
        matches = match_result.get("matches", [])
        # 端口信息完整存储
        open_ports = json.dumps(match_result.get("open_ports", []), ensure_ascii=False)
        raw_json = json.dumps(result_data, ensure_ascii=False)
        
        cursor.execute('''
            INSERT INTO scan_results 
            (task_id, url, url_type, parent_url, scan_time, status_code, is_success, match_count, open_ports, raw_result_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (task_id, url, url_type, parent_url, scan_time, status_code, is_success, len(matches), open_ports, raw_json))
        
        result_id = cursor.lastrowid
        
        # 保存指纹详情
        for match in matches:
            version_str = str(match.get("version", ""))
            detail_str = json.dumps(match.get("detail", []), ensure_ascii=False)
            cursor.execute('''
                INSERT INTO fingerprint_matches
                (result_id, software_name, software_type, version, match_dimension, confidence, detail)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                result_id,
                match.get("name", ""),
                match.get("type", ""),
                version_str,
                match.get("match_dimension", ""),
                match.get("confidence", 0),
                detail_str
            ))
        
        conn.commit()
        conn.close()

    def query_history(self, url_keyword="", software_name="", start_date="", end_date="", limit=200):
        """按条件查询历史记录"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = '''
            SELECT DISTINCT sr.*, st.task_name
            FROM scan_results sr
            LEFT JOIN scan_tasks st ON sr.task_id = st.id
            WHERE 1=1
        '''
        params = []
        
        if url_keyword:
            query += " AND sr.url LIKE ?"
            params.append(f"%{url_keyword}%")
        
        if start_date:
            query += " AND sr.created_at >= ?"
            params.append(f"{start_date} 00:00:00")
        
        if end_date:
            query += " AND sr.created_at <= ?"
            params.append(f"{end_date} 23:59:59")

        if software_name:
            query += " AND sr.id IN (SELECT result_id FROM fingerprint_matches WHERE software_name LIKE ?)"
            params.append(f"%{software_name}%")

        query += " ORDER BY sr.created_at DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        results = []
        for row in rows:
            result_dict = dict(row)
            # 解析端口信息
            try:
                result_dict['open_ports'] = json.loads(result_dict.get('open_ports', '[]'))
            except:
                result_dict['open_ports'] = []
            # 获取对应的指纹
            cursor.execute('SELECT * FROM fingerprint_matches WHERE result_id=?', (row['id'],))
            fps = cursor.fetchall()
            result_dict['fingerprints'] = [dict(fp) for fp in fps]
            results.append(result_dict)
        
        conn.close()
        return results


# 获取当前脚本(fp_interactive.py)所在的绝对目录
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# 强制指定指纹库必须在脚本同级目录下
DEFAULT_FP_DB_PATH = os.path.join(BASE_DIR, "fp_db.json")

class ResultProcessor:
    def __init__(self, output_dir="scan_results", fp_db_path=None):
        self.output_dir = output_dir
        self.fp_db_path = DEFAULT_FP_DB_PATH
        self.extractor = FingerprintExtractor(self.fp_db_path)
        self.nr = NetworkRequest()
        self.matcher = self._load_matcher()
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def _load_matcher(self):
        try:
            with open(self.fp_db_path, "r", encoding="utf-8") as f:
                fp_data = json.load(f)
            matcher = FingerprintMatcher(fp_data)
            print(f"[+] 指纹库加载成功，共{len(matcher.fingerprints)}条规则")
            return matcher
        except Exception as e:
            print(f"[!] 指纹库加载失败: {e}")
            return FingerprintMatcher()

    def _get_timestamp(self):
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def _format_version(self, version):
        if isinstance(version, dict):
            version_str = f"基础版本：{version.get('base','unknown')}"
            for k, v in version.items():
                if k != "base":
                    version_str += f" | {k}提取版本：{v}"
            return version_str
        return str(version)

    def format_single_result(self, url, match_result):
        if not match_result["status"]:
            return f"【扫描失败】URL：{url}\n错误原因：{match_result['msg']}\n"

        formatted = f"【扫描结果】URL：{url}\n"
        formatted += f"扫描时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        formatted += f"匹配状态：{'匹配成功' if match_result['matches'] else '未匹配到指纹'}\n"
        formatted += f"是否未知指纹：{'是' if match_result['unknown'] else '否'}\n"

        if match_result["matches"]:
            formatted += "\n=== 匹配到的指纹详情 ===\n"
            for idx, match in enumerate(match_result["matches"], 1):
                formatted += f"{idx}. 软件名称：{match['name']}\n"
                formatted += f"   类型：{match['type']}\n"
                version_str = self._format_version(match.get("version"))
                formatted += f"   版本：{version_str}\n"
                formatted += f"   匹配维度：{match['match_dimension']}\n"
                formatted += f"   匹配置信度：{match['confidence']}%\n"

        formatted += "-" * 50 + "\n"
        return formatted

    def format_batch_results(self, url_list, match_results):
        total = len(url_list)
        success_count = sum(1 for res in match_results if res["status"])
        match_count = sum(1 for res in match_results if res["matches"])
        unknown_count = sum(1 for res in match_results if res["unknown"] and res["status"])

        summary = f"【批量扫描汇总】\n"
        summary += f"总扫描URL数：{total}\n"
        summary += f"成功扫描数：{success_count}\n"
        summary += f"匹配到指纹数：{match_count}\n"
        summary += f"未知指纹数：{unknown_count}\n"
        summary += "=" * 60 + "\n\n"

        for url, res in zip(url_list, match_results):
            summary += self.format_single_result(url, res) + "\n"

        return summary

    def export_single_result(self, url, match_result, export_format="txt"):
        safe_url = url.replace("http://", "").replace("https://", "").replace("/", "_").replace(":", "_")
        filename = f"single_scan_{safe_url}_{self._get_timestamp()}.{export_format}"
        file_path = os.path.join(self.output_dir, filename)

        try:
            if export_format == "txt":
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(self.format_single_result(url, match_result))
            elif export_format == "json":
                export_data = {
                    "url": url,
                    "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "match_result": match_result
                }
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(export_data, f, ensure_ascii=False, indent=2)
            elif export_format == "csv":
                with open(file_path, "w", encoding="utf-8", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["URL", "扫描时间", "匹配状态", "软件名称", "类型", "版本", "匹配维度", "置信度"])
                    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    if match_result["matches"]:
                        for match in match_result["matches"]:
                            version_str = self._format_version(match.get("version"))
                            writer.writerow([
                                url, scan_time, "匹配成功",
                                match["name"], match["type"], version_str,
                                match["match_dimension"], f"{match['confidence']}%"
                            ])
                    else:
                        writer.writerow([url, scan_time, "未匹配到指纹", "", "", "", "", ""])
            else:
                print(f"错误：不支持的导出格式 {export_format}")
                return None
            print(f"单个结果已导出：{file_path}")
            return file_path
        except Exception as e:
            print(f"导出失败：{str(e)}")
            return None

    def export_batch_results(self, url_list, match_results, export_format="txt"):
        filename = f"batch_scan_{self._get_timestamp()}.{export_format}"
        file_path = os.path.join(self.output_dir, filename)

        try:
            if export_format == "txt":
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(self.format_batch_results(url_list, match_results))
            elif export_format == "json":
                export_data = {
                    "summary": {
                        "total_urls": len(url_list),
                        "success_count": sum(1 for res in match_results if res["status"]),
                        "match_count": sum(1 for res in match_results if res["matches"]),
                        "unknown_count": sum(1 for res in match_results if res["unknown"] and res["status"]),
                        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    },
                    "details": [
                        {"url": url, "result": res} for url, res in zip(url_list, match_results)
                    ]
                }
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(export_data, f, ensure_ascii=False, indent=2)
            elif export_format == "csv":
                with open(file_path, "w", encoding="utf-8", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["URL", "扫描状态", "匹配状态", "软件名称", "类型", "版本", "匹配维度", "置信度"])
                    for url, res in zip(url_list, match_results):
                        if not res["status"]:
                            writer.writerow([url, "失败", res["msg"], "", "", "", "", ""])
                            continue
                        if res["matches"]:
                            for match in res["matches"]:
                                version_str = self._format_version(match.get("version"))
                                writer.writerow([
                                    url, "成功", "匹配成功",
                                    match["name"], match["type"], version_str,
                                    match["match_dimension"], f"{match['confidence']}%"
                                ])
                        else:
                            writer.writerow([url, "成功", "未匹配到指纹", "", "", "", "", ""])
            else:
                print(f"错误：不支持的导出格式 {export_format}")
                return None
            print(f"批量结果已导出：{file_path}")
            return file_path
        except Exception as e:
            print(f"批量导出失败：{str(e)}")
            return None

    def show_visual_result(self, url, match_result):
        RED = "\033[31m"
        GREEN = "\033[32m"
        YELLOW = "\033[33m"
        RESET = "\033[0m"

        print(f"\n{GREEN}========== 扫描结果 =========={RESET}")
        print(f"{YELLOW}目标URL：{RESET}{url}")

        if not match_result["status"]:
            print(f"{RED}扫描失败：{match_result['msg']}{RESET}")
        else:
            print(f"{GREEN}扫描成功{RESET}")
            if match_result["matches"]:
                print(f"{GREEN}发现指纹：{len(match_result['matches'])} 个{RESET}")
                for match in match_result["matches"]:
                    version_str = self._format_version(match.get("version"))
                    print(f"\n软件：{match['name']}")
                    print(f"类型：{match['type']}")
                    print(f"版本：{version_str}")
                    print(f"匹配维度：{match['match_dimension']}")
                    print(f"置信度：{match['confidence']}%")
            else:
                print(f"{YELLOW}未匹配到指纹{RESET}")

        open_ports = match_result.get("open_ports", [])
        subdomains = match_result.get("subdomains", [])
        if open_ports:
            print(f"\n{YELLOW}开放端口：{RESET}{', '.join(map(str, open_ports))}")
        if subdomains:
            print(f"{YELLOW}发现子域名：{RESET}{', '.join(subdomains)}")

    def scan_and_process_single_url(self, url, export_format=None, full_html=False, port_scan=False, subdomain_detect=False, progress_callback=None):
        def _update_progress(step):
            if progress_callback:
                progress_callback(step)
        
        _update_progress(0)
        resp = self.nr.send_request(url, scan_full_html=full_html)
        _update_progress(20)
        
        request_info = {
            "status_code": "200" if resp["status"] else "Failed",
            "html_length": len(resp.get("html_content", "")),
            "protocol": url.split("://")[0] if "://" in url else "http"
        }

        open_ports = []
        if port_scan:
            domain = self.nr.preprocessor.parse_url(url)["domain"]
            self.nr.port_scanner.timeout = 1
            open_ports = self.nr.port_scanner.scan(domain)
            _update_progress(35)

        found_subdomains = []
        if subdomain_detect:
            domain = self.nr.preprocessor.parse_url(url)["domain"]
            found_subdomains = self.nr.subdomain_detector.detect(domain)
            _update_progress(50)

        extract_result = self.extractor.get_all_features(url, self.nr, full_html=full_html)
        _update_progress(60)
        
        if not extract_result["status"]:
            match_result = {
                "status": False,
                "msg": extract_result["msg"],
                "matches": [],
                "unknown": True,
                "open_ports": open_ports,
                "subdomains": found_subdomains
            }
            self.show_visual_result(url, match_result)
            result_data = {
                "url": url,
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "status": False,
                "match_result": match_result,
                "export_path": None,
                "request_info": request_info
            }
            return result_data

        features = extract_result["features"]
        match_response = {
            "body": features["html_tag"],
            "title": features["title"],
            "headers": features["http_header"],
            "header_text": features["header_text"],
            "favicon": self.nr.get_favicon(url),
            "version": features.get("version", "")
        }

        _update_progress(70)
        match_list = self.matcher.match(match_response)
        _update_progress(90)
        
        match_result = {
            "status": True,
            "msg": "扫描完成",
            "matches": match_list,
            "unknown": len(match_list) == 0,
            "open_ports": open_ports,
            "subdomains": found_subdomains
        }
        
        self.show_visual_result(url, match_result)
        export_path = None
        if export_format:
            export_path = self.export_single_result(url, match_result, export_format)
        
        _update_progress(100)
        
        result_data = {
            "url": url,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": match_result["status"],
            "match_result": match_result,
            "export_path": export_path,
            "request_info": request_info
        }

        return result_data

    def scan_and_process_batch_urls(self, url_list, export_format=None, full_html=False):
        single_results = []
        match_results = []

        print(f"\n[*] 开始批量扫描，共 {len(url_list)} 个URL")

        for idx, url in enumerate(url_list, 1):
            print(f"\n[{idx}/{len(url_list)}] 正在扫描：{url}")
            single_res = self.scan_and_process_single_url(url, export_format=None, full_html=full_html)
            single_results.append(single_res)
            match_result = single_res.get("match_result", {"status": False, "msg": "未知错误", "matches": [], "unknown": True})
            match_results.append(match_result)
            status = "匹配成功" if match_result.get("matches") else "未匹配到指纹"
            print(f"[{idx}/{len(url_list)}] 扫描完成：{url} → {status}")

        print("\n" + "=" * 60)
        print(self.format_batch_results(url_list, match_results))

        export_path = None
        if export_format:
            export_path = self.export_batch_results(url_list, match_results, export_format)

        return {
            "total": len(url_list),
            "single_results": single_results,
            "match_results": match_results,
            "export_path": export_path
        }

    def close(self):
        if hasattr(self.nr, 'close'):
            self.nr.close()