import json
import os

# 默认指纹库路径
DEFAULT_DB_PATH = "fp_db.json"


class FingerprintDBManager:
    """指纹库管理类（适配当前 fp_db.json 结构）"""

    def __init__(self, db_path=None):
        self.db_path = db_path if db_path else DEFAULT_DB_PATH
        self._ensure_db_exists()

    def _ensure_db_exists(self):
        """确保文件存在"""
        if not os.path.exists(self.db_path):
            default_db = {"fingerprint": []}
            with open(self.db_path, "w", encoding="utf-8") as f:
                json.dump(default_db, f, indent=2, ensure_ascii=False)

    def _load_raw(self):
        """加载原始数据（兼容 fingerprint / fingerprints）"""
        self._ensure_db_exists()
        with open(self.db_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # 兼容两种字段
        if "fingerprint" in data:
            return data["fingerprint"]
        elif "fingerprints" in data:
            return data["fingerprints"]
        else:
            return []

    def _save_raw(self, fingerprints):
        """保存数据（统一写入 fingerprint）"""
        data = {"fingerprint": fingerprints}
        with open(self.db_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def load_all_fingerprints(self):
        """获取所有指纹"""
        return self._load_raw()

    def save_all_fingerprints(self, fingerprints):
        """保存所有指纹"""
        self._save_raw(fingerprints)

    def query_fingerprint(self):
        """查询接口（给GUI用）"""
        return self.load_all_fingerprints()

    def add_fingerprint(self, new_fp):
        """
        添加指纹
        判重逻辑：cms + method + location + keyword
        """
        fps = self._load_raw()

        for fp in fps:
            if (
                fp.get("cms") == new_fp.get("cms")
                and fp.get("method") == new_fp.get("method")
                and fp.get("location") == new_fp.get("location")
                and fp.get("keyword") == new_fp.get("keyword")
            ):
                return False  # 已存在

        fps.append(new_fp)
        self._save_raw(fps)
        return True

    def update_fingerprint(self, old_fp, update_data):
        """
        更新指纹（用完整对象匹配）
        update_data: 要更新的字段字典
        """
        fps = self._load_raw()
        for idx, fp in enumerate(fps):
            # 精确匹配原始指纹
            if (
                fp.get("cms") == old_fp.get("cms")
                and fp.get("method") == old_fp.get("method")
                and fp.get("location") == old_fp.get("location")
                and fp.get("keyword") == old_fp.get("keyword")
            ):
                fps[idx].update(update_data)
                self._save_raw(fps)
                return True
        return False

    def delete_fingerprint(self, target_fp):
        """
        删除指纹（精确匹配）
        """
        fps = self._load_raw()
        new_fps = [fp for fp in fps if not (
            fp.get("cms") == target_fp.get("cms")
            and fp.get("method") == target_fp.get("method")
            and fp.get("location") == target_fp.get("location")
            and fp.get("keyword") == target_fp.get("keyword")
        )]

        if len(new_fps) == len(fps):
            return False

        self._save_raw(new_fps)
        return True

    # ===================== 【新增】导出指纹库 =====================
    def export_fingerprints(self, file_path):
        """
        导出指纹库到文件
        支持格式：.json
        """
        try:
            fps = self._load_raw()
            export_data = {"fingerprint": fps, "export_time": __import__("time").strftime("%Y-%m-%d %H:%M:%S")}
            
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            return True, len(fps)
        except Exception as e:
            return False, str(e)

    # ===================== 【新增】导入指纹库 =====================
    def import_fingerprints(self, file_path, skip_duplicate=True):
        """
        从文件导入指纹库
        :param file_path: 导入文件路径
        :param skip_duplicate: 是否跳过重复指纹（True=跳过，False=覆盖）
        :return: (成功状态, 导入数量, 跳过数量, 错误信息)
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                import_data = json.load(f)

            # 兼容多种数据结构
            if "fingerprint" in import_data:
                new_fps = import_data["fingerprint"]
            elif "fingerprints" in import_data:
                new_fps = import_data["fingerprints"]
            elif isinstance(import_data, list):
                new_fps = import_data
            else:
                return False, 0, 0, "无法识别的指纹库格式"

            current_fps = self._load_raw()
            import_count = 0
            skip_count = 0

            for fp in new_fps:
                # 验证指纹格式
                if not all(k in fp for k in ["cms", "method", "location", "keyword"]):
                    continue

                # 检查重复
                is_duplicate = False
                for existing_fp in current_fps:
                    if (
                        existing_fp.get("cms") == fp.get("cms")
                        and existing_fp.get("method") == fp.get("method")
                        and existing_fp.get("location") == fp.get("location")
                        and existing_fp.get("keyword") == fp.get("keyword")
                    ):
                        is_duplicate = True
                        break

                if is_duplicate:
                    if skip_duplicate:
                        skip_count += 1
                        continue
                    else:
                        # 覆盖模式：删除旧的
                        current_fps = [f for f in current_fps if not (
                            f.get("cms") == fp.get("cms")
                            and f.get("method") == fp.get("method")
                            and f.get("location") == fp.get("location")
                            and f.get("keyword") == fp.get("keyword")
                        )]

                current_fps.append(fp)
                import_count += 1

            self._save_raw(current_fps)
            return True, import_count, skip_count, ""

        except Exception as e:
            return False, 0, 0, str(e)


# 测试
if __name__ == "__main__":
    db = FingerprintDBManager()

    test_fp = {
        "cms": "测试CMS",
        "method": "keyword",
        "location": "body",
        "keyword": ["test123"]
    }

    print("添加:", db.add_fingerprint(test_fp))
    print("所有:", db.query_fingerprint())