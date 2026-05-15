#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web指纹识别交互式命令行工具
适配修复后的指纹匹配逻辑，支持单URL扫描、批量URL扫描、结果导出
新增：端口扫描、子域名探测、并发控制、超时、代理配置
【新增】扫描结果自动存入历史数据库 (与GUI共用)
"""
import argparse
import sys
import os
import json
import threading
import queue
import re
import ipaddress
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from fp_result_processor import ResultProcessor, ScanHistoryDB  # 【修改】导入 ScanHistoryDB
from colorama import init, Fore, Style

# 获取当前脚本所在的目录
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# 拼接指纹库的绝对路径
FP_DB_PATH = os.path.join(BASE_DIR, 'fp_db.json')
# 初始化colorama（跨平台彩色输出）
init(autoreset=True)


def parse_target_to_urls(target):
    """解析目标为URL列表（支持IP/CIDR/范围）"""
    from urllib.parse import urlparse
    target = target.strip()
    result = []

    parsed = urlparse(target)
    if parsed.scheme in ("http", "https"):
        return [target]

    cidr_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$'
    if re.match(cidr_pattern, target):
        try:
            network = ipaddress.IPv4Network(target, strict=False)
            if network.num_addresses > 4096:
                raise ValueError(f"网段过大，最大支持4096个IP（/20），当前网段有{network.num_addresses}个IP")
            for ip in network.hosts():
                result.append(str(ip))
            return result
        except Exception as e:
            raise ValueError(f"CIDR格式错误: {str(e)}")

    ip_range_pattern = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$'
    range_match = re.match(ip_range_pattern, target)
    if range_match:
        try:
            start_ip = ipaddress.IPv4Address(range_match.group(1))
            end_ip = ipaddress.IPv4Address(range_match.group(2))
            if start_ip > end_ip:
                raise ValueError("起始IP不能大于结束IP")
            ip_count = int(end_ip) - int(start_ip) + 1
            if ip_count > 4096:
                raise ValueError(f"IP范围过大，最大支持4096个IP，当前范围有{ip_count}个IP")
            for ip_int in range(int(start_ip), int(end_ip) + 1):
                result.append(str(ipaddress.IPv4Address(ip_int)))
            return result
        except Exception as e:
            raise ValueError(f"IP范围格式错误: {str(e)}")

    return [target]


class InteractiveScanner:
    def __init__(self, fp_db_path="fp_db.json", output_dir="scan_results",
                 concurrency=5, timeout=10,
                 proxy_enabled=False, proxy_http="", proxy_https=""):
        """初始化扫描器"""
        self.fp_db_path = fp_db_path
        self.output_dir = output_dir
        self.concurrency = concurrency
        self.timeout = timeout
        
        # 代理配置
        self.proxy_enabled = proxy_enabled
        self.proxy_http = proxy_http
        self.proxy_https = proxy_https

        # 【新增】初始化历史数据库 (与GUI共用 scan_history.db)
        self.history_db = ScanHistoryDB()
        self.db_lock = threading.Lock()  # 数据库写入锁 (多线程安全)

        # 检查指纹库文件是否存在
        if not os.path.exists(FP_DB_PATH):
            print(f"{Fore.RED}[!] 错误：指纹库文件 {FP_DB_PATH} 不存在，请确认文件路径！")
            sys.exit(1)
        
        # 确保输出目录存在
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # 初始化结果处理器（自动加载指纹库）
        self.processor = ResultProcessor(output_dir=output_dir, fp_db_path=fp_db_path)
        self.shared_matcher = self.processor.matcher
        
        print(f"{Fore.GREEN}[+] 初始化完成，指纹库路径：{fp_db_path}")
        print(f"{Fore.GREEN}[+] 结果输出目录：{output_dir}")
        print(f"{Fore.BLUE}[*] 并发数：{concurrency} | 超时：{timeout}秒")
        if proxy_enabled:
            print(f"{Fore.BLUE}[*] 代理已启用：HTTP={proxy_http} | HTTPS={proxy_https}")

    def scan_single_url(self, url, export_format=None, full_html=False, 
                       port_scan=False, subdomain_detect=False, subdomain_max_level=2):
        """扫描单个URL（支持子域名递归）"""
        print(f"\n{Fore.BLUE}[*] 开始扫描URL：{url}")
        
        # 解析目标
        try:
            initial_targets = parse_target_to_urls(url)
        except Exception as e:
            print(f"{Fore.RED}[!] 目标解析失败：{str(e)}")
            return None

        # 【新增】创建数据库扫描任务
        task_name = f"CLI单扫_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        with self.db_lock:
            task_id = self.history_db.save_scan_task(
                task_name, datetime.now().isoformat(), len(initial_targets)
            )
        print(f"{Fore.CYAN}[*] 历史任务已创建 (ID: {task_id})")

        # 准备扫描队列
        scan_queue = queue.Queue()
        scanned_urls = set()
        all_results = []
        lock = threading.Lock()

        for t in initial_targets:
            if t not in scanned_urls:
                scan_queue.put((t, "main", None))
                scanned_urls.add(t)

        print(f"{Fore.CYAN}[*] 初始目标数：{scan_queue.qsize()}")
        if subdomain_detect:
            print(f"{Fore.CYAN}[*] 子域名递归探测已开启，最大级数：{subdomain_max_level}")

        # 工作线程函数
        def worker():
            while True:
                try:
                    target_url, url_type, parent_url = scan_queue.get(timeout=2)
                except queue.Empty:
                    break

                if not target_url.startswith("http"):
                    target_url = f"http://{target_url}"

                # 判断是否为IP
                is_ip_target = False
                try:
                    ipaddress.IPv4Address(target_url.replace("http://", "").replace("https://", "").split(":")[0])
                    is_ip_target = True
                except:
                    pass

                print(f"{Fore.BLUE}[*] 正在扫描 [{url_type}]：{target_url}")

                # 初始化网络请求
                from network_request import NetworkRequest
                nr = NetworkRequest(timeout=self.timeout)
                
                if self.proxy_enabled:
                    proxies = {}
                    if self.proxy_http:
                        proxies["http"] = self.proxy_http
                    if self.proxy_https:
                        proxies["https"] = self.proxy_https
                    if proxies:
                        nr.set_proxy(proxies)

                # 临时Processor
                processor = ResultProcessor(output_dir=self.output_dir, fp_db_path=self.fp_db_path)
                processor.matcher = self.shared_matcher
                processor.nr = nr

                # 子域名探测逻辑
                if url_type == "main" and subdomain_detect and not is_ip_target:
                    try:
                        domain = nr.preprocessor.parse_url(target_url)["domain"]
                        print(f"{Fore.CYAN}[*] 正在探测子域名：{domain}")
                        alive_subdomains = nr.subdomain_detector.recursive_detect(domain, max_level=subdomain_max_level)
                        
                        if alive_subdomains:
                            print(f"{Fore.GREEN}[+] 发现{len(alive_subdomains)}个存活子域名")
                            for subdomain in alive_subdomains:
                                sub_url = f"http://{subdomain}"
                                with lock:
                                    if sub_url not in scanned_urls:
                                        scan_queue.put((sub_url, "subdomain", target_url))
                                        scanned_urls.add(sub_url)
                    except Exception as e:
                        print(f"{Fore.YELLOW}[-] 子域名探测异常：{str(e)}")

                # 执行扫描
                try:
                    result = processor.scan_and_process_single_url(
                        target_url,
                        full_html=full_html,
                        port_scan=port_scan,
                        subdomain_detect=False
                    )
                    result["url_type"] = url_type
                    result["parent_url"] = parent_url
                    all_results.append(result)
                    self._print_single_result(result)
                    
                    # 【新增】存入历史数据库
                    with self.db_lock:
                        self.history_db.save_scan_result(task_id, result)
                        
                except Exception as e:
                    print(f"{Fore.RED}[!] 扫描异常 ({target_url}): {str(e)}")
                finally:
                    nr.close()
                    scan_queue.task_done()

        # 启动线程池
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            for _ in range(self.concurrency):
                executor.submit(worker)

        scan_queue.join()
        
        # 【新增】更新数据库任务状态
        success_count = sum(1 for r in all_results if r and r.get("status"))
        with self.db_lock:
            self.history_db.update_scan_task(task_id, datetime.now().isoformat(), success_count)
        print(f"{Fore.GREEN}[+] 历史记录已保存")

        # 导出
        if export_format and all_results:
            self._export_results(all_results, export_format, prefix="single")

        return all_results

    def scan_batch_urls(self, file_path, export_format=None, full_html=False,
                       port_scan=False, subdomain_detect=False, subdomain_max_level=2):
        """批量扫描URL（从文件读取）"""
        if not os.path.exists(file_path):
            print(f"{Fore.RED}[!] 错误：URL列表文件 {file_path} 不存在！")
            return None
        
        # 读取URL列表
        with open(file_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
        
        if not lines:
            print(f"{Fore.YELLOW}[!] 警告：URL列表文件为空！")
            return None

        # 解析所有目标
        all_targets = []
        for line in lines:
            try:
                targets = parse_target_to_urls(line)
                all_targets.extend(targets)
            except Exception as e:
                print(f"{Fore.YELLOW}[-] 跳过解析失败的行 '{line}': {str(e)}")

        # 去重
        all_targets = list(dict.fromkeys(all_targets))
        
        if not all_targets:
            print(f"{Fore.RED}[!] 未解析到有效目标")
            return None

        # 【新增】创建数据库扫描任务
        task_name = f"CLI批量_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        with self.db_lock:
            task_id = self.history_db.save_scan_task(
                task_name, datetime.now().isoformat(), len(all_targets)
            )
        print(f"{Fore.CYAN}[*] 历史任务已创建 (ID: {task_id})")

        print(f"\n{Fore.BLUE}[*] 开始批量扫描，共 {len(all_targets)} 个目标")
        
        all_results = []
        scanned_urls = set()
        lock = threading.Lock()
        scan_queue = queue.Queue()

        for t in all_targets:
            if t not in scanned_urls:
                scan_queue.put((t, "main", None))
                scanned_urls.add(t)

        # 工作线程（逻辑同上）
        def worker():
            while True:
                try:
                    target_url, url_type, parent_url = scan_queue.get(timeout=3)
                except queue.Empty:
                    break

                if not target_url.startswith("http"):
                    target_url = f"http://{target_url}"

                is_ip_target = False
                try:
                    ipaddress.IPv4Address(target_url.replace("http://", "").replace("https://", "").split(":")[0])
                    is_ip_target = True
                except:
                    pass

                from network_request import NetworkRequest
                nr = NetworkRequest(timeout=self.timeout)
                if self.proxy_enabled:
                    proxies = {}
                    if self.proxy_http: proxies["http"] = self.proxy_http
                    if self.proxy_https: proxies["https"] = self.proxy_https
                    if proxies: nr.set_proxy(proxies)

                processor = ResultProcessor(output_dir=self.output_dir, fp_db_path=self.fp_db_path)
                processor.matcher = self.shared_matcher
                processor.nr = nr

                # 子域名探测
                if url_type == "main" and subdomain_detect and not is_ip_target:
                    try:
                        domain = nr.preprocessor.parse_url(target_url)["domain"]
                        alive_subdomains = nr.subdomain_detector.recursive_detect(domain, max_level=subdomain_max_level)
                        if alive_subdomains:
                            for subdomain in alive_subdomains:
                                sub_url = f"http://{subdomain}"
                                with lock:
                                    if sub_url not in scanned_urls:
                                        scan_queue.put((sub_url, "subdomain", target_url))
                                        scanned_urls.add(sub_url)
                    except:
                        pass

                try:
                    result = processor.scan_and_process_single_url(
                        target_url, full_html=full_html, port_scan=port_scan
                    )
                    result["url_type"] = url_type
                    result["parent_url"] = parent_url
                    all_results.append(result)
                    self._print_single_result(result)
                    
                    # 【新增】存入历史数据库
                    with self.db_lock:
                        self.history_db.save_scan_result(task_id, result)
                        
                except Exception as e:
                    print(f"{Fore.RED}[!] 扫描失败 ({target_url}): {str(e)}")
                finally:
                    nr.close()
                    scan_queue.task_done()

        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            for _ in range(self.concurrency):
                executor.submit(worker)
        
        scan_queue.join()

        # 【新增】更新数据库任务状态
        success_count = sum(1 for r in all_results if r and r.get("status"))
        with self.db_lock:
            self.history_db.update_scan_task(task_id, datetime.now().isoformat(), success_count)
        print(f"{Fore.GREEN}[+] 历史记录已保存")

        # 汇总
        print(f"\n{Fore.GREEN}[+] 批量扫描完成！")
        print(f"{Fore.BLUE}[*] 总计：{len(all_results)} 个目标")
        print(f"{Fore.GREEN}[*] 成功：{success_count} 个")
        print(f"{Fore.RED}[*] 失败：{len(all_results) - success_count} 个")

        if export_format:
            self._export_results(all_results, export_format, prefix="batch")

        return all_results

    def _export_results(self, results, export_format, prefix="result"):
        """统一导出逻辑"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{prefix}_scan_{timestamp}.{export_format}"
        filepath = os.path.join(self.output_dir, filename)

        try:
            if export_format == "json":
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(results, f, ensure_ascii=False, indent=2, default=str)
            
            elif export_format == "csv":
                import csv
                with open(filepath, "w", encoding="utf-8", newline="") as f:
                    fieldnames = ["URL", "类型", "父级URL", "状态", "匹配指纹数", "软件名称", "置信度", "开放端口", "扫描时间"]
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    for data in results:
                        if not data: continue
                        url = data.get("url", "")
                        url_type = data.get("url_type", "main")
                        parent_url = data.get("parent_url", "")
                        status = "成功" if data.get("status") else "失败"
                        match_result = data.get("match_result", {})
                        matches = match_result.get("matches", [])
                        open_ports = match_result.get("open_ports", [])
                        scan_time = data.get("scan_time", "")
                        
                        ports_str = ";".join(map(str, open_ports)) if open_ports else ""
                        
                        if matches:
                            for match in matches:
                                writer.writerow({
                                    "URL": url,
                                    "类型": "主域名" if url_type == "main" else "子域名",
                                    "父级URL": parent_url or "",
                                    "状态": status,
                                    "匹配指纹数": len(matches),
                                    "软件名称": match.get('name', ''),
                                    "置信度": f"{match.get('confidence', 0)}%",
                                    "开放端口": ports_str,
                                    "扫描时间": scan_time
                                })
                        else:
                            writer.writerow({
                                "URL": url, "类型": "主域名" if url_type == "main" else "子域名",
                                "父级URL": parent_url or "", "状态": status, "匹配指纹数": 0,
                                "软件名称": "", "置信度": "", "开放端口": ports_str, "扫描时间": scan_time
                            })
            
            elif export_format == "txt":
                with open(filepath, "w", encoding="utf-8") as f:
                    for data in results:
                        if not data: continue
                        f.write(f"{'='*60}\n")
                        f.write(f"目标URL: {data.get('url')}\n")
                        f.write(f"扫描时间: {data.get('scan_time')}\n")
                        if data.get("status"):
                            matches = data.get("match_result", {}).get("matches", [])
                            f.write(f"匹配指纹数: {len(matches)}\n")
                            for m in matches:
                                f.write(f"  - {m.get('name')} (置信度: {m.get('confidence')}%)\n")
                        f.write("\n")

            print(f"{Fore.GREEN}[+] 结果已导出至：{filepath}")
            return filepath
        except Exception as e:
            print(f"{Fore.RED}[!] 导出失败：{str(e)}")
            return None

    def _print_single_result(self, result):
        """格式化输出单个结果"""
        if not result:
            return
        
        url = result["url"]
        status = result["status"]
        match_result = result.get("match_result", {})
        url_type = result.get("url_type", "main")
        
        prefix = f"[{url_type}]"
        print(f"\n{Style.BRIGHT}{Fore.WHITE}{'='*50}")
        print(f"{Fore.WHITE}目标: {url} {prefix}")
        
        if not status:
            print(f"{Fore.RED}[!] 状态：失败")
            print(f"{Fore.RED}[!] 原因：{match_result.get('msg', '未知错误')}")
        else:
            matches = match_result.get("matches", [])
            open_ports = match_result.get("open_ports", [])
            
            if matches:
                print(f"{Fore.GREEN}[+] 状态：成功 | 发现 {len(matches)} 个指纹")
                for idx, match in enumerate(matches, 1):
                    print(f"  {Fore.CYAN}[{idx}] {match['name']}")
                    print(f"      置信度: {match['confidence']}% | 维度: {match['match_dimension']}")
            else:
                print(f"{Fore.YELLOW}[-] 状态：成功 | 未匹配到指纹")
            
            if open_ports:
                print(f"{Fore.MAGENTA}[*] 开放端口: {', '.join(map(str, open_ports))}")
        
        print(f"{Style.BRIGHT}{Fore.WHITE}{'='*50}")


def main():
    parser = argparse.ArgumentParser(
        description="Web指纹识别交互式工具 (增强版)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例：
  1. 扫描单个URL：
     python fp_interactive.py -u https://example.com
  2. 开启端口扫描和子域名探测：
     python fp_interactive.py -u https://example.com --port-scan --subdomain-detect --subdomain-max-level 3
  3. 批量扫描并设置高并发：
     python fp_interactive.py -f urls.txt -c 20 -t 15 -e csv
  4. 使用代理扫描：
     python fp_interactive.py -u https://example.com --proxy-enabled --proxy-http http://127.0.0.1:7890
        """
    )
    
    # 核心输入参数
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="要扫描的单个目标 (URL/IP/CIDR/范围)")
    group.add_argument("-f", "--file", help="包含目标列表的文件路径")
    
    # 指纹库与输出
    parser.add_argument("-d", "--db", default="fp_db.json", help="指纹库路径 (默认: fp_db.json)")
    parser.add_argument("-e", "--export", choices=["json", "csv", "txt"], help="结果导出格式")
    parser.add_argument("-o", "--output", default="scan_results", help="输出目录 (默认: scan_results)")
    
    # 扫描性能
    parser.add_argument("-c", "--concurrency", type=int, default=5, help="并发数 (默认: 5)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="请求超时秒数 (默认: 10)")
    
    # 扫描功能开关
    parser.add_argument("--full-html", action="store_true", help="扫描完整HTML (默认仅前100KB)")
    parser.add_argument("--port-scan", action="store_true", help="开启常见端口扫描")
    parser.add_argument("--subdomain-detect", action="store_true", help="开启子域名递归探测")
    parser.add_argument("--subdomain-max-level", type=int, default=2, help="子域名最大递归级数 (默认: 2)")
    
    # 代理配置
    parser.add_argument("--proxy-enabled", action="store_true", help="启用代理")
    parser.add_argument("--proxy-http", default="", help="HTTP代理地址 (如: http://127.0.0.1:7890)")
    parser.add_argument("--proxy-https", default="", help="HTTPS代理地址")

    args = parser.parse_args()

    # 初始化并运行
    scanner = InteractiveScanner(
        fp_db_path=args.db,
        output_dir=args.output,
        concurrency=args.concurrency,
        timeout=args.timeout,
        proxy_enabled=args.proxy_enabled,
        proxy_http=args.proxy_http,
        proxy_https=args.proxy_https
    )

    if args.url:
        scanner.scan_single_url(
            args.url,
            export_format=args.export,
            full_html=args.full_html,
            port_scan=args.port_scan,
            subdomain_detect=args.subdomain_detect,
            subdomain_max_level=args.subdomain_max_level
        )
    elif args.file:
        scanner.scan_batch_urls(
            args.file,
            export_format=args.export,
            full_html=args.full_html,
            port_scan=args.port_scan,
            subdomain_detect=args.subdomain_detect,
            subdomain_max_level=args.subdomain_max_level
        )

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] 用户中断操作，程序退出")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] 程序异常退出：{str(e)}")
        sys.exit(1)