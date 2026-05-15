import sys
import threading
import queue
import re
import ipaddress
from collections import defaultdict
from datetime import datetime

from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QFileDialog, QMessageBox,
    QTreeWidget, QTreeWidgetItem, QHeaderView,
    QStackedWidget, QListWidget, QListWidgetItem,
    QTextEdit, QComboBox, QLabel, QFormLayout, QCheckBox, QProgressBar, QGroupBox, QFrame, QDateEdit
)
from PySide6.QtCore import QTimer, Qt, QSize, QDate
from PySide6.QtGui import QFont, QTextCursor, QColor, QIcon, QPalette

from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt

from fp_result_processor import ResultProcessor, ScanHistoryDB
from fp_db_manager import FingerprintDBManager


def parse_target_to_urls(target):
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


class ScanThread(threading.Thread): 
    def __init__(self, url_list, result_queue, log_queue, progress_queue, processor, 
                 full_html=False, port_scan=False, subdomain_detect=False, subdomain_max_level=2,
                 concurrency=5, timeout=10,
                 proxy_enabled=False, proxy_http="", proxy_https=""):
        super().__init__()
        self.original_urls = url_list
        self.result_queue = result_queue
        self.log_queue = log_queue
        self.progress_queue = progress_queue
        self.processor = processor
        self.full_html = full_html
        self.port_scan = port_scan
        self.subdomain_detect = subdomain_detect
        self.subdomain_max_level = subdomain_max_level
        self.concurrency = concurrency
        self.timeout = timeout
        self._is_running = True

        self.proxy_enabled = proxy_enabled
        self.proxy_http = proxy_http
        self.proxy_https = proxy_https

        self.shared_matcher = processor.matcher
        self.fp_db_path = processor.fp_db_path
        self.output_dir = processor.output_dir

        self.lock = threading.Lock()
        self.scanned_urls = set()
        self.total_tasks = 0
        self.completed_tasks = 0

    def run(self):
        from concurrent.futures import ThreadPoolExecutor, as_completed

        scan_queue = queue.Queue()
        for url in self.original_urls:
            if url not in self.scanned_urls:
                scan_queue.put((url, "main", None))
                with self.lock:
                    self.scanned_urls.add(url)
                    self.total_tasks += 1

        self.log_queue.put(f"[*] 扫描任务启动，总目标数：{len(self.original_urls)}，并发数：{self.concurrency}")
        if self.subdomain_detect:
            self.log_queue.put(f"[*] 已开启子域名递归探测，最大级数：{self.subdomain_max_level}")

        def scan_worker():
            while self._is_running:
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

                self.log_queue.put(f"[*] 正在扫描 [{url_type}]：{target_url}")

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
                        self.log_queue.put(f"[*] 已启用代理：{proxies}")

                processor = ResultProcessor(output_dir=self.output_dir, fp_db_path=self.fp_db_path)
                processor.matcher = self.shared_matcher
                processor.nr = nr

                if url_type == "main" and self.subdomain_detect and not is_ip_target:
                    try:
                        domain = nr.preprocessor.parse_url(target_url)["domain"]
                        self.log_queue.put(f"[*] 开始递归探测子域名：{domain}")
                        alive_subdomains = nr.subdomain_detector.recursive_detect(domain, max_level=self.subdomain_max_level)
                        
                        if alive_subdomains:
                            self.log_queue.put(f"[+] 探测到{len(alive_subdomains)}个存活子域名，自动加入扫描队列")
                            for subdomain in alive_subdomains:
                                sub_url = f"http://{subdomain}"
                                with self.lock:
                                    if sub_url not in self.scanned_urls:
                                        scan_queue.put((sub_url, "subdomain", target_url))
                                        self.scanned_urls.add(sub_url)
                                        self.total_tasks += 1
                        else:
                            self.log_queue.put(f"[-] 未探测到存活子域名")
                    except Exception as e:
                        self.log_queue.put(f"[!] 子域名探测异常：{str(e)}")

                def step_callback(step_progress):
                    if not self._is_running:
                        return
                    with self.lock:
                        total_steps = self.total_tasks * 100
                        current_step = self.completed_tasks * 100 + step_progress
                        total_progress = int((current_step / total_steps) * 100) if total_steps > 0 else 0
                    self.progress_queue.put(total_progress)

                try:
                    result = processor.scan_and_process_single_url(
                        target_url,
                        full_html=self.full_html,
                        port_scan=self.port_scan,
                        subdomain_detect=False,
                        progress_callback=step_callback
                    )
                    result["url_type"] = url_type
                    result["parent_url"] = parent_url
                    self.result_queue.put({"url": target_url, "result": result})
                except Exception as e:
                    self.log_queue.put(f"[!] 扫描异常 ({target_url}): {str(e)}")
                    self.result_queue.put({"url": target_url, "error": str(e)})
                finally:
                    nr.close()
                    with self.lock:
                        self.completed_tasks += 1
                    scan_queue.task_done()

        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            workers = [executor.submit(scan_worker) for _ in range(self.concurrency)]
            for future in as_completed(workers):
                if not self._is_running:
                    break

        self.progress_queue.put(100)
        self.log_queue.put("[SCAN_COMPLETE]")

    def stop(self):
        self._is_running = False
        self.log_queue.put("[!] 正在停止扫描任务...")


class PieChartCanvas(FigureCanvas):
    def __init__(self, parent=None):
        plt.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'Arial Unicode MS']
        plt.rcParams['axes.unicode_minus'] = False
        
        self.fig = Figure(figsize=(4, 3), dpi=100, facecolor='#1e293b')
        self.axes = self.fig.add_subplot(111)
        self.axes.set_facecolor('#1e293b')
        super().__init__(self.fig)
        self.setParent(parent)
        
        self.show_placeholder("暂无数据")

    def show_placeholder(self, text):
        self.axes.clear()
        self.axes.text(0.5, 0.5, text, ha='center', va='center', fontsize=12, color='#94a3b8')
        self.axes.set_axis_off()
        self.draw()

    def update_scan_result_chart(self, stats):
        self.axes.clear()
        
        total = stats.get("total", 0)
        success = stats.get("success", 0)
        failed = stats.get("failed", 0)
        matched = stats.get("matched", 0)
        unmatched = success - matched if success >= matched else 0
        
        if total == 0:
            self.show_placeholder("暂无扫描数据")
            return
        
        labels = ['匹配成功', '未匹配指纹', '扫描失败']
        sizes = [matched, unmatched, failed]
        colors = ['#10b981', '#f59e0b', '#ef4444']
        
        filtered_labels = []
        filtered_sizes = []
        filtered_colors = []
        for label, size, color in zip(labels, sizes, colors):
            if size > 0:
                filtered_labels.append(label)
                filtered_sizes.append(size)
                filtered_colors.append(color)
        
        if not filtered_sizes:
            self.show_placeholder("暂无有效数据")
            return
        
        explode = [0.05] * len(filtered_sizes)
        wedges, texts, autotexts = self.axes.pie(
            filtered_sizes,
            explode=explode,
            labels=filtered_labels,
            colors=filtered_colors,
            autopct='%1.1f%%',
            pctdistance=0.85,
            labeldistance=1.1,
            shadow=False,
            startangle=90,
            textprops={'color': '#e2e8f0'}
        )
        
        for text in texts:
            text.set_fontsize(10)
        for autotext in autotexts:
            autotext.set_fontsize(9)
            autotext.set_color('#ffffff')
        
        self.axes.set_title('扫描结果统计', fontsize=12, pad=20, color='#e2e8f0')
        self.fig.tight_layout()
        self.draw()

    def update_tech_stack_chart(self, tech_stats):
        self.axes.clear()
        
        if not tech_stats or sum(tech_stats.values()) == 0:
            self.show_placeholder("暂无技术栈数据")
            return
        
        sorted_tech = sorted(tech_stats.items(), key=lambda x: x[1], reverse=True)
        
        display_limit = 8
        top_tech = sorted_tech[:display_limit]
        other_count = sum(x[1] for x in sorted_tech[display_limit:])
        
        labels = [x[0] for x in top_tech]
        sizes = [x[1] for x in top_tech]
        
        cmap = plt.cm.get_cmap('tab20', len(labels) + 1)
        colors = [cmap(i) for i in range(len(labels))]
        
        if other_count > 0:
            labels.append('其他')
            sizes.append(other_count)
            colors.append('#64748b')
        
        explode = [0.02] * len(labels)
        wedges, texts, autotexts = self.axes.pie(
            sizes,
            explode=explode,
            labels=labels,
            colors=colors,
            autopct='%1.1f%%',
            pctdistance=0.8,
            labeldistance=1.1,
            shadow=False,
            startangle=90,
            textprops={'color': '#e2e8f0'}
        )
        
        for text in texts:
            text.set_fontsize(9)
        for autotext in autotexts:
            autotext.set_fontsize(8)
            autotext.set_color('#ffffff')
        
        self.axes.set_title('技术栈占比统计', fontsize=12, pad=20, color='#e2e8f0')
        self.fig.tight_layout()
        self.draw()


class ModernButton(QPushButton):
    def __init__(self, text, color_type="primary", parent=None):
        super().__init__(text, parent)
        self.color_type = color_type
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(36)
        self.setProperty("color_type", color_type)

    def set_color_type(self, color_type):
        self.color_type = color_type
        self.setProperty("color_type", color_type)
        self.style().unpolish(self)
        self.style().polish(self)


class FingerprintGUI(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Moon Web Fingerprint Scanner")
        self.resize(1600, 950)

        self.processor = ResultProcessor(fp_db_path="fp_db.json")
        self.db = FingerprintDBManager()
        self.history_db = ScanHistoryDB()
        
        self.result_queue = queue.Queue()
        self.log_queue = queue.Queue()
        self.progress_queue = queue.Queue()
        self.scan_thread = None

        self.scan_stats = {
            "total": 0,
            "success": 0,
            "failed": 0,
            "matched": 0
        }
        self.tech_stack_stats = defaultdict(int)

        self.all_fps = []
        self.all_scan_results = []
        self.main_url_items = {}
        
        self.current_selected_fp = None
        self.current_db_task_id = None

        self.init_ui()
        self.apply_stylesheet()

        self.timer = QTimer()
        self.timer.timeout.connect(self.check_queues)
        self.timer.start(100)

    def init_ui(self):
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        self.sidebar = QListWidget()
        self.sidebar.setFixedWidth(200)
        self.sidebar.addItem(QListWidgetItem("指纹扫描"))
        self.sidebar.addItem(QListWidgetItem("指纹库管理"))
        self.sidebar.addItem(QListWidgetItem("扫描历史"))
        self.sidebar.currentRowChanged.connect(self.switch_page)
        self.sidebar.setFrameShape(QFrame.NoFrame)

        self.content_container = QWidget()
        self.content_container.setStyleSheet("background-color: #0f172a;")
        content_layout = QVBoxLayout(self.content_container)
        content_layout.setContentsMargins(20, 20, 20, 20)
        
        self.stack = QStackedWidget()
        self.stack.setFrameShape(QFrame.NoFrame)
        self.stack.addWidget(self.build_scan_page())
        self.stack.addWidget(self.build_db_page())
        self.stack.addWidget(self.build_history_page())
        
        content_layout.addWidget(self.stack)

        main_layout.addWidget(self.sidebar)
        main_layout.addWidget(self.content_container, stretch=1)
        self.sidebar.setCurrentRow(0)

    def switch_page(self, index):
        self.stack.setCurrentIndex(index)
        if index == 2:
            self.load_history_data()

    def build_scan_page(self):
        widget = QWidget()
        main_layout = QHBoxLayout(widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(20)

        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(15)

        top_card = QGroupBox()
        top_card.setStyleSheet("""
            QGroupBox {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 12px;
                margin-top: 0px;
                padding-top: 10px;
            }
        """)
        top_layout = QVBoxLayout(top_card)
        top_layout.setContentsMargins(15, 15, 15, 15)
        
        url_row = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("输入URL/IP/IP段 (例: http://nginx.org | 192.168.1.0/24 | 192.168.1.1-192.168.1.100)")
        self.url_input.setMinimumHeight(40)
        url_row.addWidget(self.url_input, stretch=1)
        top_layout.addLayout(url_row)
        
        btn_row = QHBoxLayout()
        scan_btn = ModernButton("开始扫描", "primary")
        scan_btn.clicked.connect(self.start_scan)
        batch_btn = ModernButton("批量扫描", "secondary")
        batch_btn.clicked.connect(self.batch_scan)
        stop_btn = ModernButton("停止", "danger")
        stop_btn.clicked.connect(self.stop_scan)
        clear_btn = ModernButton("清空结果", "secondary")
        clear_btn.clicked.connect(self.clear_result)
        export_btn = ModernButton("导出结果", "secondary")
        export_btn.clicked.connect(self.export_result)

        btn_row.addWidget(scan_btn)
        btn_row.addWidget(batch_btn)
        btn_row.addWidget(stop_btn)
        btn_row.addWidget(clear_btn)
        btn_row.addWidget(export_btn)
        btn_row.addStretch()
        top_layout.addLayout(btn_row)
        
        left_layout.addWidget(top_card)

        result_card = QGroupBox("扫描结果")
        result_card.setStyleSheet("""
            QGroupBox {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 12px;
                margin-top: 0px;
                padding-top: 15px;
                font-size: 14px;
                font-weight: bold;
                color: #e2e8f0;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 5px;
            }
        """)
        result_layout = QVBoxLayout(result_card)
        result_layout.setContentsMargins(10, 15, 10, 10)
        
        self.result_tree = QTreeWidget()
        self.result_tree.setColumnCount(4)
        self.result_tree.setHeaderLabels(["目标URL", "类型", "匹配指纹数", "扫描时间"])
        self.result_tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.result_tree.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.result_tree.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.result_tree.header().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.result_tree.setAlternatingRowColors(False)
        self.result_tree.setRootIsDecorated(False)
        result_layout.addWidget(self.result_tree)
        left_layout.addWidget(result_card, stretch=1)

        progress_card = QGroupBox()
        progress_card.setStyleSheet("""
            QGroupBox {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 12px;
                margin-top: 0px;
                padding-top: 10px;
            }
        """)
        progress_layout = QVBoxLayout(progress_card)
        progress_layout.setContentsMargins(15, 15, 15, 15)
        progress_label = QLabel("扫描进度")
        progress_label.setStyleSheet("color: #94a3b8; font-weight: bold;")
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setAlignment(Qt.AlignCenter)
        self.progress_bar.setFormat("%p%")
        self.progress_bar.setMinimumHeight(25)
        progress_layout.addWidget(progress_label)
        progress_layout.addWidget(self.progress_bar)
        left_layout.addWidget(progress_card)

        log_card = QGroupBox("终端输出")
        log_card.setStyleSheet("""
            QGroupBox {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 12px;
                margin-top: 0px;
                padding-top: 15px;
                font-size: 14px;
                font-weight: bold;
                color: #e2e8f0;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 5px;
            }
        """)
        log_layout = QVBoxLayout(log_card)
        log_layout.setContentsMargins(10, 15, 10, 10)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(180)
        log_layout.addWidget(self.log_text)
        left_layout.addWidget(log_card)

        right_widget = QWidget()
        right_widget.setFixedWidth(340)
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(15)

        scan_group = QGroupBox("扫描选项")
        scan_group.setStyleSheet("""
            QGroupBox {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 12px;
                margin-top: 0px;
                padding-top: 15px;
                font-size: 14px;
                font-weight: bold;
                color: #e2e8f0;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 5px;
            }
        """)
        scan_layout = QVBoxLayout(scan_group)
        scan_layout.setContentsMargins(15, 20, 15, 15)
        
        self.full_html_checkbox = QCheckBox("完整HTML扫描")
        self.full_html_checkbox.setStyleSheet("color: #cbd5e1; spacing: 8px;")
        self.port_scan_checkbox = QCheckBox("端口扫描")
        self.port_scan_checkbox.setStyleSheet("color: #cbd5e1; spacing: 8px;")
        
        self.subdomain_checkbox = QCheckBox("子域名递归探测")
        self.subdomain_checkbox.setStyleSheet("color: #cbd5e1; spacing: 8px;")
        self.subdomain_checkbox.stateChanged.connect(self.toggle_subdomain_config)
        
        subdomain_level_layout = QHBoxLayout()
        subdomain_level_label = QLabel("最大递归级数:")
        subdomain_level_label.setStyleSheet("color: #94a3b8;")
        self.subdomain_level_combo = QComboBox()
        self.subdomain_level_combo.addItems(["1", "2", "3", "4", "5"])
        self.subdomain_level_combo.setCurrentIndex(1)
        self.subdomain_level_combo.setEnabled(False)
        subdomain_level_layout.addWidget(subdomain_level_label)
        subdomain_level_layout.addWidget(self.subdomain_level_combo)

        scan_layout.addWidget(self.full_html_checkbox)
        scan_layout.addWidget(self.port_scan_checkbox)
        scan_layout.addWidget(self.subdomain_checkbox)
        scan_layout.addLayout(subdomain_level_layout)
        right_layout.addWidget(scan_group)

        request_group = QGroupBox("请求配置")
        request_group.setStyleSheet("""
            QGroupBox {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 12px;
                margin-top: 0px;
                padding-top: 15px;
                font-size: 14px;
                font-weight: bold;
                color: #e2e8f0;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 5px;
            }
        """)
        request_layout = QFormLayout(request_group)
        request_layout.setContentsMargins(15, 20, 15, 15)
        request_layout.setHorizontalSpacing(10)
        request_layout.setVerticalSpacing(12)
        
        concurrency_label = QLabel("并发数:")
        concurrency_label.setStyleSheet("color: #94a3b8;")
        self.concurrency_spin = QComboBox()
        self.concurrency_spin.addItems(["1", "5", "10", "20", "50"])
        self.concurrency_spin.setCurrentIndex(1)
        
        timeout_label = QLabel("超时(秒):")
        timeout_label.setStyleSheet("color: #94a3b8;")
        self.timeout_spin = QComboBox()
        self.timeout_spin.addItems(["5", "10", "15", "30", "60"])
        self.timeout_spin.setCurrentIndex(1)
        
        request_layout.addRow(concurrency_label, self.concurrency_spin)
        request_layout.addRow(timeout_label, self.timeout_spin)
        right_layout.addWidget(request_group)

        proxy_group = QGroupBox("代理配置")
        proxy_group.setStyleSheet("""
            QGroupBox {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 12px;
                margin-top: 0px;
                padding-top: 15px;
                font-size: 14px;
                font-weight: bold;
                color: #e2e8f0;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 5px;
            }
        """)
        proxy_layout = QVBoxLayout(proxy_group)
        proxy_layout.setContentsMargins(15, 20, 15, 15)
        
        self.proxy_checkbox = QCheckBox("启用代理")
        self.proxy_checkbox.setStyleSheet("color: #cbd5e1; spacing: 8px;")
        proxy_layout.addWidget(self.proxy_checkbox)
        
        proxy_form = QFormLayout()
        proxy_form.setHorizontalSpacing(10)
        proxy_form.setVerticalSpacing(10)
        proxy_http_label = QLabel("HTTP代理:")
        proxy_http_label.setStyleSheet("color: #94a3b8;")
        self.proxy_http_input = QLineEdit()
        self.proxy_http_input.setPlaceholderText("http://127.0.0.1:7890")
        
        proxy_https_label = QLabel("HTTPS代理:")
        proxy_https_label.setStyleSheet("color: #94a3b8;")
        self.proxy_https_input = QLineEdit()
        self.proxy_https_input.setPlaceholderText("http://127.0.0.1:7890")
        
        proxy_form.addRow(proxy_http_label, self.proxy_http_input)
        proxy_form.addRow(proxy_https_label, self.proxy_https_input)
        proxy_layout.addLayout(proxy_form)
        right_layout.addWidget(proxy_group)

        chart_group = QGroupBox("扫描统计")
        chart_group.setStyleSheet("""
            QGroupBox {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 12px;
                margin-top: 0px;
                padding-top: 15px;
                font-size: 14px;
                font-weight: bold;
                color: #e2e8f0;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 5px;
            }
        """)
        chart_layout = QVBoxLayout(chart_group)
        chart_layout.setContentsMargins(10, 15, 10, 10)

        switch_btn_layout = QHBoxLayout()
        self.btn_page_scan = ModernButton("扫描概览", "primary")
        self.btn_page_scan.setCheckable(True)
        self.btn_page_scan.setChecked(True)
        self.btn_page_scan.clicked.connect(lambda: self.switch_chart_view(0))
        
        self.btn_page_tech = ModernButton("技术栈", "secondary")
        self.btn_page_tech.setCheckable(True)
        self.btn_page_tech.clicked.connect(lambda: self.switch_chart_view(1))

        switch_btn_layout.addWidget(self.btn_page_scan)
        switch_btn_layout.addWidget(self.btn_page_tech)
        chart_layout.addLayout(switch_btn_layout)

        self.chart_stack = QStackedWidget()
        self.pie_chart_scan = PieChartCanvas()
        self.chart_stack.addWidget(self.pie_chart_scan)
        self.pie_chart_tech = PieChartCanvas()
        self.chart_stack.addWidget(self.pie_chart_tech)

        chart_layout.addWidget(self.chart_stack)
        
        self.stats_label = QLabel("总目标: 0 | 成功: 0 | 失败: 0 | 匹配: 0")
        self.stats_label.setStyleSheet("font-size: 11px; color:#94a3b8; padding: 5px;")
        chart_layout.addWidget(self.stats_label)
        
        right_layout.addWidget(chart_group, stretch=1)

        main_layout.addWidget(left_widget, stretch=1)
        main_layout.addWidget(right_widget)

        return widget

    def toggle_subdomain_config(self):
        is_checked = self.subdomain_checkbox.isChecked()
        self.subdomain_level_combo.setEnabled(is_checked)

    def build_db_page(self):
        widget = QWidget()
        main_layout = QHBoxLayout(widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(20)

        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(15)

        search_card = QGroupBox()
        search_card.setStyleSheet("""
            QGroupBox {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 12px;
                margin-top: 0px;
                padding-top: 10px;
            }
        """)
        search_layout = QHBoxLayout(search_card)
        search_layout.setContentsMargins(15, 15, 15, 15)
        search_label = QLabel("搜索CMS:")
        search_label.setStyleSheet("color: #94a3b8; font-weight: bold;")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("输入CMS名称关键词...")
        self.search_input.setMinimumHeight(36)
        self.search_input.textChanged.connect(self.filter_fp_table)
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_input, stretch=1)
        left_layout.addWidget(search_card)

        table_card = QGroupBox("指纹库列表")
        table_card.setStyleSheet("""
            QGroupBox {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 12px;
                margin-top: 0px;
                padding-top: 15px;
                font-size: 14px;
                font-weight: bold;
                color: #e2e8f0;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 5px;
            }
        """)
        table_layout = QVBoxLayout(table_card)
        table_layout.setContentsMargins(10, 15, 10, 10)
        
        self.fp_table = QTreeWidget()
        self.fp_table.setColumnCount(4)
        self.fp_table.setHeaderLabels(["CMS", "方法", "位置", "关键字"])
        self.fp_table.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.fp_table.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.fp_table.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.fp_table.header().setSectionResizeMode(3, QHeaderView.Stretch)
        self.fp_table.setRootIsDecorated(False)
        self.fp_table.itemClicked.connect(self.load_selected_fp_to_form)
        table_layout.addWidget(self.fp_table)
        left_layout.addWidget(table_card, stretch=1)

        right_widget = QWidget()
        right_widget.setFixedWidth(360)
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(15)

        form_card = QGroupBox("编辑指纹")
        form_card.setStyleSheet("""
            QGroupBox {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 12px;
                margin-top: 0px;
                padding-top: 15px;
                font-size: 14px;
                font-weight: bold;
                color: #e2e8f0;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 5px;
            }
        """)
        form_layout = QFormLayout(form_card)
        form_layout.setContentsMargins(15, 20, 15, 15)
        form_layout.setHorizontalSpacing(10)
        form_layout.setVerticalSpacing(12)
        
        cms_label = QLabel("CMS名称:")
        cms_label.setStyleSheet("color: #94a3b8;")
        self.fp_cms_input = QLineEdit()
        self.fp_cms_input.setPlaceholderText("例如: Nginx")
        self.fp_cms_input.setMinimumHeight(36)
        
        method_label = QLabel("匹配方法:")
        method_label.setStyleSheet("color: #94a3b8;")
        self.fp_method_combo = QComboBox()
        self.fp_method_combo.addItems(["keyword", "faviconhash"])
        self.fp_method_combo.setMinimumHeight(36)
        
        location_label = QLabel("匹配位置:")
        location_label.setStyleSheet("color: #94a3b8;")
        self.fp_location_combo = QComboBox()
        self.fp_location_combo.addItems(["body", "title", "header"])
        self.fp_location_combo.setMinimumHeight(36)
        
        keyword_label = QLabel("关键字:")
        keyword_label.setStyleSheet("color: #94a3b8;")
        self.fp_keyword_input = QLineEdit()
        self.fp_keyword_input.setPlaceholderText("多个关键字用逗号分隔")
        self.fp_keyword_input.setMinimumHeight(36)

        form_layout.addRow(cms_label, self.fp_cms_input)
        form_layout.addRow(method_label, self.fp_method_combo)
        form_layout.addRow(location_label, self.fp_location_combo)
        form_layout.addRow(keyword_label, self.fp_keyword_input)
        right_layout.addWidget(form_card)

        btn_card = QGroupBox()
        btn_card.setStyleSheet("""
            QGroupBox {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 12px;
                margin-top: 0px;
                padding-top: 10px;
            }
        """)
        btn_layout = QVBoxLayout(btn_card)
        btn_layout.setContentsMargins(15, 15, 15, 15)
        btn_layout.setSpacing(10)
        
        add_btn = ModernButton("添加指纹", "primary")
        add_btn.clicked.connect(self.add_fp)
        update_btn = ModernButton("修改指纹", "warning")
        update_btn.clicked.connect(self.update_fp)
        del_btn = ModernButton("删除选中", "danger")
        del_btn.clicked.connect(self.delete_fp)
        refresh_btn = ModernButton("刷新列表", "secondary")
        refresh_btn.clicked.connect(self.load_fp_table)

        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(update_btn)
        btn_layout.addWidget(del_btn)
        btn_layout.addWidget(refresh_btn)
        right_layout.addWidget(btn_card)

        io_card = QGroupBox()
        io_card.setStyleSheet("""
            QGroupBox {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 12px;
                margin-top: 0px;
                padding-top: 10px;
            }
        """)
        io_layout = QVBoxLayout(io_card)
        io_layout.setContentsMargins(15, 15, 15, 15)
        io_layout.setSpacing(10)
        
        import_btn = ModernButton("📥 导入指纹库", "success")
        import_btn.clicked.connect(self.import_fingerprints)
        export_btn = ModernButton("📤 导出指纹库", "info")
        export_btn.clicked.connect(self.export_fingerprints)

        io_layout.addWidget(import_btn)
        io_layout.addWidget(export_btn)
        right_layout.addWidget(io_card)

        right_layout.addStretch()

        main_layout.addWidget(left_widget, stretch=1)
        main_layout.addWidget(right_widget)

        self.load_fp_table()
        return widget

    def build_history_page(self):
        """构建扫描历史页面（新增开放端口列）"""
        widget = QWidget()
        main_layout = QVBoxLayout(widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(15)

        # 顶部筛选栏
        filter_card = QGroupBox("查询条件")
        filter_card.setStyleSheet("""
            QGroupBox {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 12px;
                margin-top: 0px;
                padding-top: 15px;
                font-size: 14px;
                font-weight: bold;
                color: #e2e8f0;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 5px;
            }
        """)
        filter_layout = QHBoxLayout(filter_card)
        filter_layout.setContentsMargins(15, 20, 15, 15)
        filter_layout.setSpacing(15)

        # URL关键词
        filter_layout.addWidget(QLabel("URL包含:"))
        self.hist_url_input = QLineEdit()
        self.hist_url_input.setPlaceholderText("输入URL关键词...")
        self.hist_url_input.setMaximumWidth(200)
        filter_layout.addWidget(self.hist_url_input)

        # 指纹名称
        filter_layout.addWidget(QLabel("技术栈:"))
        self.hist_fp_input = QLineEdit()
        self.hist_fp_input.setPlaceholderText("如: Nginx")
        self.hist_fp_input.setMaximumWidth(150)
        filter_layout.addWidget(self.hist_fp_input)

        # 日期范围
        filter_layout.addWidget(QLabel("开始日期:"))
        self.hist_date_start = QDateEdit()
        self.hist_date_start.setCalendarPopup(True)
        self.hist_date_start.setDate(QDate.currentDate().addDays(-30))
        self.hist_date_start.setDisplayFormat("yyyy-MM-dd")
        filter_layout.addWidget(self.hist_date_start)

        filter_layout.addWidget(QLabel("结束日期:"))
        self.hist_date_end = QDateEdit()
        self.hist_date_end.setCalendarPopup(True)
        self.hist_date_end.setDate(QDate.currentDate())
        self.hist_date_end.setDisplayFormat("yyyy-MM-dd")
        filter_layout.addWidget(self.hist_date_end)

        # 查询按钮
        search_btn = ModernButton("查询", "primary")
        search_btn.clicked.connect(self.load_history_data)
        filter_layout.addWidget(search_btn)
        
        reset_btn = ModernButton("重置", "secondary")
        reset_btn.clicked.connect(self.reset_history_filter)
        filter_layout.addWidget(reset_btn)

        filter_layout.addStretch()
        main_layout.addWidget(filter_card)

        # 结果表格（新增开放端口列）
        result_card = QGroupBox("历史记录")
        result_card.setStyleSheet("""
            QGroupBox {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 12px;
                margin-top: 0px;
                padding-top: 15px;
                font-size: 14px;
                font-weight: bold;
                color: #e2e8f0;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 5px;
            }
        """)
        result_layout = QVBoxLayout(result_card)
        result_layout.setContentsMargins(10, 15, 10, 10)
        
        self.history_tree = QTreeWidget()
        # 新增开放端口列，共7列
        self.history_tree.setColumnCount(7)
        self.history_tree.setHeaderLabels(["目标URL", "状态码", "匹配数", "开放端口", "技术栈", "扫描时间", "任务名"])
        # 列宽适配
        self.history_tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.history_tree.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.history_tree.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.history_tree.header().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.history_tree.header().setSectionResizeMode(4, QHeaderView.Stretch)
        self.history_tree.header().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.history_tree.setAlternatingRowColors(False)
        self.history_tree.setRootIsDecorated(False)
        self.history_tree.itemDoubleClicked.connect(self.show_history_detail)
        result_layout.addWidget(self.history_tree)
        main_layout.addWidget(result_card, stretch=1)

        return widget

    def reset_history_filter(self):
        self.hist_url_input.clear()
        self.hist_fp_input.clear()
        self.hist_date_start.setDate(QDate.currentDate().addDays(-30))
        self.hist_date_end.setDate(QDate.currentDate())
        self.load_history_data()

    def load_history_data(self):
        """加载历史数据（含端口信息解析与展示）"""
        self.history_tree.clear()
        
        url_kw = self.hist_url_input.text().strip()
        fp_kw = self.hist_fp_input.text().strip()
        start_d = self.hist_date_start.date().toString("yyyy-MM-dd")
        end_d = self.hist_date_end.date().toString("yyyy-MM-dd")

        try:
            records = self.history_db.query_history(
                url_keyword=url_kw,
                software_name=fp_kw,
                start_date=start_d,
                end_date=end_d,
                limit=200
            )

            for rec in records:
                item = QTreeWidgetItem(self.history_tree)
                item.setText(0, rec.get("url", ""))
                item.setText(1, rec.get("status_code", ""))
                item.setText(2, str(rec.get("match_count", 0)))
                
                # 端口信息展示
                open_ports = rec.get("open_ports", [])
                port_text = ", ".join(map(str, open_ports)) if open_ports else "无"
                item.setText(3, port_text)
                if open_ports:
                    item.setForeground(3, QColor("#f87171"))
                else:
                    item.setForeground(3, QColor("#94a3b8"))
                
                # 提取技术栈名称
                fps = rec.get("fingerprints", [])
                tech_names = ", ".join([fp.get("software_name", "") for fp in fps]) if fps else "无"
                item.setText(4, tech_names)
                
                item.setText(5, rec.get("created_at", ""))
                item.setText(6, rec.get("task_name", ""))
                
                # 存储原始数据用于详情展示
                item.setData(0, Qt.UserRole, rec)
                
                # 状态颜色
                if rec.get("is_success"):
                    item.setForeground(0, QColor("#4ade80"))
                else:
                    item.setForeground(0, QColor("#ef4444"))

        except Exception as e:
            QMessageBox.warning(self, "错误", f"加载历史记录失败: {str(e)}")

    def show_history_detail(self, item, column):
        """双击显示历史详情（新增端口信息展示）"""
        rec = item.data(0, Qt.UserRole)
        if not rec:
            return

        # 构建详情弹窗
        detail_msg = f"""
        <h3>扫描详情</h3>
        <b>URL:</b> {rec.get('url')}<br>
        <b>时间:</b> {rec.get('created_at')}<br>
        <b>任务:</b> {rec.get('task_name', 'N/A')}<br>
        <b>状态码:</b> {rec.get('status_code', 'N/A')}<br>
        """
        
        # 端口信息
        open_ports = rec.get("open_ports", [])
        if open_ports:
            detail_msg += f"<b>开放端口:</b> <span style='color:#f87171'>{', '.join(map(str, open_ports))}</span><br>"
        else:
            detail_msg += "<b>开放端口:</b> 无<br>"
        
        detail_msg += "<br>"
        
        fps = rec.get("fingerprints", [])
        if fps:
            detail_msg += "<h4>匹配指纹:</h4><ul>"
            for fp in fps:
                detail_msg += f"<li><b>{fp.get('software_name')}</b> (置信度: {fp.get('confidence')}%)</li>"
            detail_msg += "</ul>"
        else:
            detail_msg += "<p style='color:#fbbf24'>未匹配到指纹</p>"

        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("历史记录详情")
        msg_box.setTextFormat(Qt.RichText)
        msg_box.setText(detail_msg)
        msg_box.exec()

    def load_selected_fp_to_form(self, item):
        if not item:
            return
        cms = item.text(0)
        method = item.text(1)
        location = item.text(2)
        keyword_str = item.text(3)

        try:
            keyword = eval(keyword_str) if keyword_str.startswith('[') else [keyword_str]
        except:
            keyword = [keyword_str]

        self.current_selected_fp = {
            "cms": cms,
            "method": method,
            "location": location,
            "keyword": keyword
        }

        self.fp_cms_input.setText(cms)
        self.fp_method_combo.setCurrentText(method)
        self.fp_location_combo.setCurrentText(location)
        self.fp_keyword_input.setText(", ".join(keyword))

    def update_fp(self):
        if not self.current_selected_fp:
            QMessageBox.warning(self, "提示", "请先在列表中选择要修改的指纹")
            return

        cms = self.fp_cms_input.text().strip()
        method = self.fp_method_combo.currentText()
        location = self.fp_location_combo.currentText()
        keyword_str = self.fp_keyword_input.text().strip()

        if not cms or not keyword_str:
            QMessageBox.warning(self, "提示", "CMS名称和关键字不能为空")
            return

        keywords = [k.strip() for k in keyword_str.split(",") if k.strip()]
        update_data = {
            "cms": cms,
            "method": method,
            "location": location,
            "keyword": keywords
        }

        if self.db.update_fingerprint(self.current_selected_fp, update_data):
            QMessageBox.information(self, "成功", "指纹修改成功！")
            self.load_fp_table()
            self.fp_cms_input.clear()
            self.fp_keyword_input.clear()
            self.current_selected_fp = None
        else:
            QMessageBox.warning(self, "失败", "指纹修改失败，原始指纹不存在或已变更")

    def import_fingerprints(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "导入指纹库", "", "JSON 文件 (*.json)"
        )
        if not file_path:
            return

        reply = QMessageBox.question(
            self, "导入选项", "遇到重复指纹时是否跳过？\n\n"
                              "【是】跳过重复指纹（推荐）\n"
                              "【否】覆盖原有指纹",
            QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel
        )
        
        if reply == QMessageBox.Cancel:
            return
        
        skip_duplicate = (reply == QMessageBox.Yes)

        success, import_count, skip_count, error_msg = self.db.import_fingerprints(file_path, skip_duplicate)

        if success:
            msg = f"导入成功！\n\n新增指纹：{import_count} 条"
            if skip_count > 0:
                msg += f"\n跳过重复：{skip_count} 条"
            QMessageBox.information(self, "成功", msg)
            self.load_fp_table()
        else:
            QMessageBox.warning(self, "导入失败", f"导入指纹库失败：{error_msg}")

    def export_fingerprints(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, "导出指纹库", "", "JSON 文件 (*.json)"
        )
        if not file_path:
            return

        success, count = self.db.export_fingerprints(file_path)

        if success:
            QMessageBox.information(self, "成功", f"导出成功！\n共导出 {count} 条指纹")
        else:
            QMessageBox.warning(self, "导出失败", f"导出指纹库失败：{count}")

    def append_colored_log(self, msg):
        color_map = {
            "[*]": "#38bdf8",
            "[+]": "#4ade80",
            "[!]": "#f87171",
            "[-]": "#fbbf24"
        }

        color = "#e2e8f0"
        for prefix, c in color_map.items():
            if msg.startswith(prefix):
                color = c
                break

        self.log_text.moveCursor(QTextCursor.End)
        self.log_text.insertHtml(f'<span style="color:{color};">{msg}</span><br>')
        self.log_text.moveCursor(QTextCursor.End)

    def start_scan(self):
        input_content = self.url_input.text().strip()
        if not input_content:
            QMessageBox.warning(self, "提示", "请输入URL/IP/IP段")
            return

        try:
            target_list = parse_target_to_urls(input_content)
        except Exception as e:
            QMessageBox.warning(self, "输入格式错误", str(e))
            return

        self.scan_stats = {"total": len(target_list), "success": 0, "failed": 0, "matched": 0}
        self.tech_stack_stats.clear()
        self.progress_bar.setValue(0)
        self.main_url_items.clear()
        
        # 直接在这里创建数据库任务
        task_name = f"手动扫描_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.current_db_task_id = self.history_db.save_scan_task(
            task_name, datetime.now().isoformat(), len(target_list)
        )
        
        full_html = self.full_html_checkbox.isChecked()
        port_scan = self.port_scan_checkbox.isChecked()
        subdomain_detect = self.subdomain_checkbox.isChecked()
        subdomain_max_level = int(self.subdomain_level_combo.currentText())
        concurrency = int(self.concurrency_spin.currentText())
        timeout = int(self.timeout_spin.currentText())
        
        self.append_colored_log(f"[*] 解析完成，共 {len(target_list)} 个待扫描目标")
        self.scan_thread = ScanThread(
            target_list, 
            self.result_queue, 
            self.log_queue, 
            self.progress_queue,
            self.processor, 
            full_html=full_html,
            port_scan=port_scan,
            subdomain_detect=subdomain_detect,
            subdomain_max_level=subdomain_max_level,
            concurrency=concurrency,
            timeout=timeout,
            proxy_enabled=self.proxy_checkbox.isChecked(),
            proxy_http=self.proxy_http_input.text().strip(),
            proxy_https=self.proxy_https_input.text().strip()
        )
        self.scan_thread.start()

    def batch_scan(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择URL文件", "", "Text Files (*.txt)"
        )
        if not file_path:
            return
        
        target_list = []
        line_error = []
        with open(file_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line_content = line.strip()
                if not line_content:
                    continue
                try:
                    targets = parse_target_to_urls(line_content)
                    target_list.extend(targets)
                except Exception as e:
                    line_error.append(f"第{line_num}行: {str(e)}")
        
        if line_error:
            QMessageBox.warning(self, "文件解析警告", "\n".join(line_error))
        
        if not target_list:
            QMessageBox.warning(self, "提示", "未解析到有效目标")
            return
        
        target_list = list(dict.fromkeys(target_list))
        
        self.scan_stats = {"total": len(target_list), "success": 0, "failed": 0, "matched": 0}
        self.tech_stack_stats.clear()
        self.progress_bar.setValue(0)
        self.main_url_items.clear()
        
        # 直接在这里创建数据库任务
        task_name = f"批量扫描_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.current_db_task_id = self.history_db.save_scan_task(
            task_name, datetime.now().isoformat(), len(target_list)
        )

        self.append_colored_log(f"[*] 批量解析完成，共 {len(target_list)} 个待扫描目标")
        full_html = self.full_html_checkbox.isChecked()
        port_scan = self.port_scan_checkbox.isChecked()
        subdomain_detect = self.subdomain_checkbox.isChecked()
        subdomain_max_level = int(self.subdomain_level_combo.currentText())
        concurrency = int(self.concurrency_spin.currentText())
        timeout = int(self.timeout_spin.currentText())
        
        self.scan_thread = ScanThread(
            target_list, 
            self.result_queue, 
            self.log_queue, 
            self.progress_queue,
            self.processor, 
            full_html=full_html,
            port_scan=port_scan,
            subdomain_detect=subdomain_detect,
            subdomain_max_level=subdomain_max_level,
            concurrency=concurrency,
            timeout=timeout,
            proxy_enabled=self.proxy_checkbox.isChecked(),
            proxy_http=self.proxy_http_input.text().strip(),
            proxy_https=self.proxy_https_input.text().strip()
        )
        self.scan_thread.start()

    def stop_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.stop()

    def check_queues(self):
        while not self.progress_queue.empty():
            progress = self.progress_queue.get()
            self.progress_bar.setValue(progress)
        
        while not self.log_queue.empty():
            log_msg = self.log_queue.get()
            if log_msg == "[SCAN_COMPLETE]":
                self.show_scan_summary()
                # 标记数据库任务完成
                if self.current_db_task_id:
                    success_count = self.scan_stats.get("success", 0)
                    self.history_db.update_scan_task(self.current_db_task_id, datetime.now().isoformat(), success_count)
                continue
            self.append_colored_log(log_msg)
        
        while not self.result_queue.empty():
            data = self.result_queue.get()
            url = data["url"]
            
            if "error" in data:
                self.scan_stats["failed"] += 1
                self.append_colored_log(f"[!] 扫描失败: {url} - {data['error']}")
                self.update_all_charts()
                continue
            
            self.scan_stats["success"] += 1
            result = data["result"]
            url_type = result.get("url_type", "main")
            parent_url = result.get("parent_url")
            match_result = result.get("match_result", {})
            matches = match_result.get("matches", [])

            self.all_scan_results.append(result)
            
            # 存入数据库 (核心修复)
            if self.current_db_task_id:
                try:
                    # 补充上 url_type 和 parent_url，因为数据库需要
                    result_for_db = result.copy()
                    result_for_db["url_type"] = url_type
                    result_for_db["parent_url"] = parent_url
                    self.history_db.save_scan_result(self.current_db_task_id, result_for_db)
                except Exception as e:
                    print(f"[Debug] 保存历史记录失败: {e}")

            if matches:
                self.scan_stats["matched"] += 1
                self.append_colored_log(f"[+] 扫描完成 [{url_type}]: {url} - 发现{len(matches)}个指纹")
                for match in matches:
                    tech_name = match.get('name', '未知')
                    self.tech_stack_stats[tech_name] += 1
            else:
                self.append_colored_log(f"[-] 扫描完成 [{url_type}]: {url} - 未匹配到指纹")

            self.display_result(url, result, url_type, parent_url)
            self.update_all_charts()

    def switch_chart_view(self, index):
        self.chart_stack.setCurrentIndex(index)
        if index == 0:
            self.btn_page_scan.setChecked(True)
            self.btn_page_tech.setChecked(False)
            self.btn_page_scan.set_color_type("primary")
            self.btn_page_tech.set_color_type("secondary")
        else:
            self.btn_page_scan.setChecked(False)
            self.btn_page_tech.setChecked(True)
            self.btn_page_scan.set_color_type("secondary")
            self.btn_page_tech.set_color_type("primary")

    def update_all_charts(self):
        self.pie_chart_scan.update_scan_result_chart(self.scan_stats)
        self.pie_chart_tech.update_tech_stack_chart(self.tech_stack_stats)
        
        total = self.scan_stats.get("total", 0)
        success = self.scan_stats.get("success", 0)
        failed = self.scan_stats.get("failed", 0)
        matched = self.scan_stats.get("matched", 0)
        self.stats_label.setText(f"总目标: {total} | 成功: {success} | 失败: {failed} | 匹配: {matched}")

    def show_scan_summary(self):
        self.progress_bar.setValue(100)
        stats = self.scan_stats
        summary_msg = (
            f"扫描任务完成！\n\n"
            f"总扫描目标数: {stats['total']}\n"
            f"成功扫描: {stats['success']}\n"
            f"扫描失败: {stats['failed']}\n"
            f"匹配到指纹: {stats['matched']}\n"
        )
        QMessageBox.information(self, "扫描完成", summary_msg)

    def display_result(self, url, result, url_type, parent_url):
        match_result = result.get("match_result", {})
        matches = match_result.get("matches", [])
        open_ports = match_result.get("open_ports", [])
        scan_time = result.get("scan_time", "")

        current_item = QTreeWidgetItem()
        current_item.setText(0, url)
        current_item.setText(1, "主域名" if url_type == "main" else "子域名")
        current_item.setText(2, str(len(matches)))
        current_item.setText(3, scan_time)

        if url_type == "main":
            current_item.setBackground(0, QColor("#1e3a5f"))
            current_item.setBackground(1, QColor("#1e3a5f"))
            current_item.setBackground(2, QColor("#1e3a5f"))
            current_item.setBackground(3, QColor("#1e3a5f"))
            current_item.setForeground(0, QColor("#e0f2fe"))
            current_item.setForeground(1, QColor("#e0f2fe"))
            current_item.setForeground(2, QColor("#e0f2fe"))
            current_item.setForeground(3, QColor("#e0f2fe"))
            font = current_item.font(0)
            font.setBold(True)
            current_item.setFont(0, font)
        else:
            current_item.setBackground(0, QColor("#1e293b"))
            current_item.setBackground(1, QColor("#1e293b"))
            current_item.setBackground(2, QColor("#1e293b"))
            current_item.setBackground(3, QColor("#1e293b"))
            current_item.setForeground(0, QColor("#cbd5e1"))
            current_item.setForeground(1, QColor("#cbd5e1"))
            current_item.setForeground(2, QColor("#cbd5e1"))
            current_item.setForeground(3, QColor("#cbd5e1"))

        if matches:
            current_item.setForeground(1, QColor("#4ade80"))
        else:
            current_item.setForeground(1, QColor("#fbbf24"))

        if url_type == "main":
            self.result_tree.addTopLevelItem(current_item)
            self.main_url_items[url] = current_item
        else:
            if parent_url in self.main_url_items:
                parent_item = self.main_url_items[parent_url]
                parent_item.addChild(current_item)
                parent_item.setExpanded(True)
            else:
                self.result_tree.addTopLevelItem(current_item)

        if matches:
            for idx, match in enumerate(matches, 1):
                fp_group_item = QTreeWidgetItem(current_item)
                fp_group_item.setText(0, f"指纹 {idx}: {match.get('name', '未知')}")
                fp_group_item.setFirstColumnSpanned(True)
                fp_group_item.setForeground(0, QColor("#38bdf8"))
                fp_group_item.setBackground(0, QColor("#1e1b4b"))

                details = [
                    (f"  软件名称: {match.get('name', '')}", "#e2e8f0"),
                    (f"  类型: {match.get('type', '')}", "#94a3b8"),
                    (f"  版本: {self._format_version_str(match.get('version', ''))}", "#cbd5e1"),
                    (f"  匹配维度: {match.get('match_dimension', '')}", "#94a3b8"),
                    (f"  置信度: {match.get('confidence', 0)}%", "#4ade80")
                ]
                
                for detail_text, color in details:
                    detail_item = QTreeWidgetItem(fp_group_item)
                    detail_item.setText(0, detail_text)
                    detail_item.setFirstColumnSpanned(True)
                    detail_item.setForeground(0, QColor(color))
                    detail_item.setBackground(0, QColor("#0f172a"))

        if open_ports:
            port_item = QTreeWidgetItem(current_item)
            port_item.setText(0, f"开放端口: {', '.join(map(str, open_ports))}")
            port_item.setFirstColumnSpanned(True)
            port_item.setForeground(0, QColor("#f87171"))
            port_item.setBackground(0, QColor("#450a0a"))

        current_item.setExpanded(False)

    def _format_version_str(self, version):
        if isinstance(version, dict):
            version_str = f"基础版本：{version.get('base','unknown')}"
            for k, v in version.items():
                if k != "base":
                    version_str += f" | {k}提取版本：{v}"
            return version_str
        return str(version)

    def clear_result(self):
        self.result_tree.clear()
        self.log_text.clear()
        self.progress_bar.setValue(0)
        self.scan_stats = {"total":0,"success":0,"failed":0,"matched":0}
        self.tech_stack_stats.clear()
        self.all_scan_results = []
        self.main_url_items.clear()
        self.update_all_charts()

    def export_result(self):
        file_path, file_type = QFileDialog.getSaveFileName(
            self, "导出结果", "", "Excel 文件 (*.xlsx);;Text 文件 (*.txt);;CSV 文件 (*.csv);;JSON 文件 (*.json)"
        )
        if not file_path:
            return

        try:
            if file_path.endswith(".xlsx"):
                self.export_to_excel(file_path)
            elif file_path.endswith(".json"):
                import json
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(self.all_scan_results, f, ensure_ascii=False, indent=2)
            elif file_path.endswith(".csv"):
                with open(file_path, "w", encoding="utf-8", newline="") as f:
                    f.write("URL,类型,父级URL,状态,匹配指纹数,软件名称,类型,版本,匹配维度,置信度,开放端口,扫描时间\n")
                    for data in self.all_scan_results:
                        url = data["url"]
                        url_type = data.get("url_type", "main")
                        parent_url = data.get("parent_url", "")
                        match_result = data.get("match_result", {})
                        matches = match_result.get("matches", [])
                        open_ports = match_result.get("open_ports", [])
                        scan_time = data.get("scan_time", "")
                        
                        ports_str = ";".join(map(str, open_ports)) if open_ports else ""
                        status = "成功" if matches else "未匹配"
                        
                        if matches:
                            for match in matches:
                                row = [
                                    url, url_type, parent_url, status, str(len(matches)),
                                    match.get('name', ''), match.get('type', ''),
                                    str(match.get('version', '')).replace("\n", " ").replace(",", ";"),
                                    match.get('match_dimension', ''), f"{match.get('confidence', 0)}%",
                                    ports_str, scan_time
                                ]
                                f.write(",".join(f'"{cell}"' for cell in row) + "\n")
                        else:
                            row = [
                                url, url_type, parent_url, status, "0",
                                "", "", "", "", "", ports_str, scan_time
                            ]
                            f.write(",".join(f'"{cell}"' for cell in row) + "\n")
            else:
                with open(file_path, "w", encoding="utf-8") as f:
                    for data in self.all_scan_results:
                        url = data["url"]
                        url_type = data.get("url_type", "main")
                        parent_url = data.get("parent_url", "")
                        match_result = data.get("match_result", {})
                        matches = match_result.get("matches", [])
                        open_ports = match_result.get("open_ports", [])
                        scan_time = data.get("scan_time", "")
                        
                        f.write(f"{'='*60}\n")
                        f.write(f"目标URL: {url}\n")
                        f.write(f"类型: {'主域名' if url_type == 'main' else '子域名'}\n")
                        if parent_url:
                            f.write(f"父级域名: {parent_url}\n")
                        f.write(f"扫描时间: {scan_time}\n")
                        f.write(f"匹配指纹数: {len(matches)}\n")
                        if open_ports:
                            f.write(f"开放端口: {', '.join(map(str, open_ports))}\n")
                        
                        if matches:
                            f.write(f"\n--- 匹配指纹详情 ---\n")
                            for idx, match in enumerate(matches, 1):
                                f.write(f"\n指纹 {idx}:\n")
                                f.write(f"  软件名称: {match.get('name', '')}\n")
                                f.write(f"  类型: {match.get('type', '')}\n")
                                f.write(f"  版本: {self._format_version_str(match.get('version', ''))}\n")
                                f.write(f"  匹配维度: {match.get('match_dimension', '')}\n")
                                f.write(f"  置信度: {match.get('confidence', 0)}%\n")
                        
                        f.write(f"\n")
            
            self.append_colored_log(f"[+] 结果已导出至: {file_path}")
        except Exception as e:
            self.append_colored_log(f"[!] 导出失败: {str(e)}")
            QMessageBox.warning(self, "导出失败", f"导出结果时发生错误: {str(e)}")

    def export_to_excel(self, file_path):
        from openpyxl import Workbook
        wb = Workbook()
        ws = wb.active
        ws.title = "扫描结果"

        headers = [
            "URL", "类型", "父级URL", "状态", "匹配指纹数",
            "软件名称", "类型", "版本", "匹配维度", "置信度", "开放端口", "扫描时间"
        ]
        ws.append(headers)

        for data in self.all_scan_results:
            url = data["url"]
            url_type = data.get("url_type", "main")
            parent_url = data.get("parent_url", "")
            match_result = data.get("match_result", {})
            matches = match_result.get("matches", [])
            open_ports = match_result.get("open_ports", [])
            scan_time = data.get("scan_time", "")
            ports_str = ";".join(map(str, open_ports)) if open_ports else ""
            status = "成功" if matches else "未匹配"

            if matches:
                for match in matches:
                    row = [
                        url,
                        "主域名" if url_type == "main" else "子域名",
                        parent_url,
                        status,
                        len(matches),
                        match.get("name", ""),
                        match.get("type", ""),
                        str(match.get("version", "")),
                        match.get("match_dimension", ""),
                        f"{match.get('confidence', 0)}%",
                        ports_str,
                        scan_time
                    ]
                    ws.append(row)
            else:
                row = [
                    url,
                    "主域名" if url_type == "main" else "子域名",
                    parent_url,
                    status,
                    0, "", "", "", "", "", ports_str, scan_time
                ]
                ws.append(row)

        wb.save(file_path)

    def load_fp_table(self):
        self.all_fps = self.db.load_all_fingerprints()
        self.fill_fp_table(self.all_fps)

    def fill_fp_table(self, fingerprints):
        self.fp_table.clear()
        for fp in fingerprints:
            item = QTreeWidgetItem(self.fp_table)
            item.setText(0, fp.get("cms", ""))
            item.setText(1, fp.get("method", ""))
            item.setText(2, fp.get("location", ""))
            item.setText(3, str(fp.get("keyword", "")))
            item.setForeground(0, QColor("#e2e8f0"))
            item.setForeground(1, QColor("#94a3b8"))
            item.setForeground(2, QColor("#94a3b8"))
            item.setForeground(3, QColor("#cbd5e1"))
            item.setBackground(0, QColor("#1e293b"))
            item.setBackground(1, QColor("#1e293b"))
            item.setBackground(2, QColor("#1e293b"))
            item.setBackground(3, QColor("#1e293b"))

    def filter_fp_table(self):
        keyword = self.search_input.text().strip().lower()
        if not keyword:
            filtered = self.all_fps
        else:
            filtered = [fp for fp in self.all_fps if keyword in fp.get("cms", "").lower()]
        self.fill_fp_table(filtered)

    def add_fp(self):
        cms = self.fp_cms_input.text().strip()
        method = self.fp_method_combo.currentText()
        location = self.fp_location_combo.currentText()
        keyword_str = self.fp_keyword_input.text().strip()

        if not cms or not keyword_str:
            QMessageBox.warning(self, "提示", "请填写CMS名称和关键字")
            return

        keywords = [k.strip() for k in keyword_str.split(",") if k.strip()]

        new_fp = {
            "cms": cms,
            "method": method,
            "location": location,
            "keyword": keywords
        }

        if self.db.add_fingerprint(new_fp):
            self.load_fp_table()
            self.fp_cms_input.clear()
            self.fp_keyword_input.clear()
            QMessageBox.information(self, "成功", "指纹添加成功")
        else:
            QMessageBox.warning(self, "提示", "该指纹已存在")

    def delete_fp(self):
        current_item = self.fp_table.currentItem()
        if not current_item:
            QMessageBox.warning(self, "提示", "请先选择要删除的指纹")
            return
        
        cms = current_item.text(0)
        method = current_item.text(1)
        location = current_item.text(2)
        keyword_str = current_item.text(3)
        try:
            keyword = eval(keyword_str) if keyword_str.startswith('[') else [keyword_str]
        except:
            keyword = [keyword_str]

        fp = {
            "cms": cms,
            "method": method,
            "location": location,
            "keyword": keyword
        }

        reply = QMessageBox.question(
            self, "确认", "确定要删除选中的指纹吗？",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            if self.db.delete_fingerprint(fp):
                self.load_fp_table()
            else:
                QMessageBox.warning(self, "提示", "删除失败，可能指纹已不存在")

    def apply_stylesheet(self):
        self.setStyleSheet("""
        /* 全局样式 */
        QWidget {
            background-color: #0f172a;
            color: #e2e8f0;
            font-family: "Microsoft YaHei UI", "Segoe UI", sans-serif;
            font-size: 13px;
        }

        /* 侧边栏 */
        QListWidget {
            background-color: #1e293b;
            border: none;
            outline: none;
            padding: 10px 0px;
        }
        QListWidget::item {
            padding: 14px 20px;
            margin: 4px 12px;
            border-radius: 8px;
            color: #94a3b8;
            font-size: 14px;
        }
        QListWidget::item:hover {
            background-color: #334155;
            color: #e2e8f0;
        }
        QListWidget::item:selected {
            background-color: #3b82f6;
            color: white;
        }

        /* 输入框 */
        QLineEdit {
            background-color: #0f172a;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 8px 12px;
            color: #e2e8f0;
        }
        QLineEdit:focus {
            border: 1px solid #3b82f6;
            background-color: #1e293b;
        }
        QLineEdit:hover {
            border: 1px solid #475569;
        }

        /* 下拉框 */
        QComboBox {
            background-color: #0f172a;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 8px 12px;
            padding-right: 36px;
            color: #e2e8f0;
            selection-background-color: #3b82f6;
            outline: none;
        }
        QComboBox:hover {
            border: 1px solid #475569;
            background-color: #1e293b;
        }
        QComboBox:focus {
            border: 1px solid #3b82f6;
            background-color: #1e293b;
        }
        QComboBox::drop-down {
            subcontrol-origin: padding;
            subcontrol-position: top right;
            width: 36px;
            border: none;
            background-color: transparent;
        }
        QComboBox::down-arrow {
            image: none;
            border-left: 5px solid transparent;
            border-right: 5px solid transparent;
            border-top: 5px solid #94a3b8;
            width: 0;
            height: 0;
        }
        QComboBox QAbstractItemView {
            background-color: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
            outline: none;
            padding: 4px;
        }
        QComboBox QAbstractItemView::item {
            background-color: #1e293b;
            color: #e2e8f0;
            padding: 8px 12px;
            border-radius: 4px;
            margin: 2px 4px;
        }
        QComboBox QAbstractItemView::item:hover {
            background-color: #334155;
        }
        QComboBox QAbstractItemView::item:selected {
            background-color: #3b82f6;
            color: white;
        }

        /* 按钮 */
        ModernButton {
            border: none;
            border-radius: 8px;
            padding: 8px 20px;
            font-weight: 600;
            font-size: 13px;
            color: white;
        }
        ModernButton[color_type="primary"] {
            background-color: #3b82f6;
        }
        ModernButton[color_type="primary"]:hover {
            background-color: #2563eb;
        }
        ModernButton[color_type="primary"]:pressed {
            background-color: #1d4ed8;
        }
        ModernButton[color_type="primary"]:checked {
            background-color: #1d4ed8;
            border: 1px solid #60a5fa;
        }
        ModernButton[color_type="secondary"] {
            background-color: #475569;
        }
        ModernButton[color_type="secondary"]:hover {
            background-color: #64748b;
        }
        ModernButton[color_type="secondary"]:pressed {
            background-color: #334155;
        }
        ModernButton[color_type="secondary"]:checked {
            background-color: #3b82f6;
        }
        ModernButton[color_type="danger"] {
            background-color: #ef4444;
        }
        ModernButton[color_type="danger"]:hover {
            background-color: #dc2626;
        }
        ModernButton[color_type="danger"]:pressed {
            background-color: #b91c1c;
        }
        ModernButton[color_type="warning"] {
            background-color: #f59e0b;
        }
        ModernButton[color_type="warning"]:hover {
            background-color: #d97706;
        }
        ModernButton[color_type="warning"]:pressed {
            background-color: #b45309;
        }
        ModernButton[color_type="success"] {
            background-color: #10b981;
        }
        ModernButton[color_type="success"]:hover {
            background-color: #059669;
        }
        ModernButton[color_type="success"]:pressed {
            background-color: #047857;
        }
        ModernButton[color_type="info"] {
            background-color: #06b6d4;
        }
        ModernButton[color_type="info"]:hover {
            background-color: #0891b2;
        }
        ModernButton[color_type="info"]:pressed {
            background-color: #0e7490;
        }

        /* 表格 */
        QTreeWidget {
            background-color: #0f172a;
            border: none;
            outline: none;
            gridline-color: #334155;
        }
        QTreeWidget::item {
            padding: 8px;
            border: none;
        }
        QTreeWidget::item:selected {
            background-color: #1e3a5f;
            color: #e0f2fe;
        }
        QTreeWidget::item:hover {
            background-color: #334155;
        }
        QHeaderView::section {
            background-color: #1e293b;
            color: #94a3b8;
            padding: 12px 8px;
            border: none;
            border-bottom: 1px solid #334155;
            font-weight: bold;
            font-size: 12px;
        }

        /* 复选框 */
        QCheckBox {
            spacing: 10px;
        }
        QCheckBox::indicator {
            width: 20px;
            height: 20px;
            border: 2px solid #475569;
            border-radius: 4px;
            background-color: #0f172a;
        }
        QCheckBox::indicator:hover {
            border: 2px solid #3b82f6;
        }
        QCheckBox::indicator:checked {
            background-color: #3b82f6;
            border: 2px solid #3b82f6;
            image: url(none);
        }

        /* 进度条 */
        QProgressBar {
            border: 1px solid #334155;
            border-radius: 6px;
            text-align: center;
            height: 22px;
            background-color: #0f172a;
            color: #e2e8f0;
        }
        QProgressBar::chunk {
            background-color: #3b82f6;
            border-radius: 5px;
        }

        /* 日志终端 */
        QTextEdit {
            background-color: #020617;
            color: #e2e8f0;
            font-family: "Consolas", "Monaco", "Courier New", monospace;
            font-size: 12px;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 10px;
        }

        /* 日期选择器 */
        QDateEdit {
            background-color: #0f172a;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 6px;
            color: #e2e8f0;
        }
        QDateEdit::drop-down {
            border: none;
            width: 20px;
        }
        QDateEdit::down-arrow {
            border-left: 4px solid transparent;
            border-right: 4px solid transparent;
            border-top: 4px solid #94a3b8;
        }

        /* 滚动条 */
        QScrollBar:vertical {
            background-color: #0f172a;
            width: 10px;
            border-radius: 5px;
            margin: 0px;
        }
        QScrollBar::handle:vertical {
            background-color: #475569;
            min-height: 30px;
            border-radius: 5px;
        }
        QScrollBar::handle:vertical:hover {
            background-color: #64748b;
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0px;
        }
        QScrollBar:horizontal {
            background-color: #0f172a;
            height: 10px;
            border-radius: 5px;
            margin: 0px;
        }
        QScrollBar::handle:horizontal {
            background-color: #475569;
            min-width: 30px;
            border-radius: 5px;
        }
        QScrollBar::handle:horizontal:hover {
            background-color: #64748b;
        }
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
            width: 0px;
        }
        """)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setAttribute(Qt.AA_DontUseNativeDialogs, True)
    app.setAttribute(Qt.AA_DontUseNativeMenuBar, True)
    app.setAttribute(Qt.AA_UseStyleSheetPropagationInWidgetStyles, True)
    window = FingerprintGUI()
    window.show()
    sys.exit(app.exec())