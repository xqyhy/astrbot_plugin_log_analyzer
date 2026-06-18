"""日志分析器插件 — 自动监控、抓取、分析、修复一条龙！"""

import asyncio
import json
import os
import re
import time
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from astrbot import logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.platform import Platform
from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_message_event import (
    AiocqhttpMessageEvent,
)

try:
    from astrbot.api.star import Context, Star, StarTools, register
except ImportError:
    from astrbot.api import Context, Star, StarTools, register

DEFAULT_LOG_PATH = "/AstrBot/data/logs/astrbot.log"

# 告警级别定义
ALERT_LEVELS = {
    "critical": {"name": "🔴 严重", "priority": 1},
    "error": {"name": "🟠 错误", "priority": 2},
    "warning": {"name": "🟡 警告", "priority": 3},
    "info": {"name": "🔵 信息", "priority": 4},
}


@register("astrbot_plugin_log_analyzer", "小七月", "日志分析器：自动监控、抓取、分析、修复", "v1.2.0")
class LogAnalyzerPlugin(Star):
    """
    日志分析器插件：
    - 自动监控日志关键词，发现后自动发送给管理员
    - 告警阈值 + 静默期，减少打扰
    - 关键词分级，区分严重程度
    - 热更新配置，修改配置无需重启
    - 错误统计，了解系统健康状况
    """

    def __init__(self, context: Context, config=None):
        super().__init__(context)
        self.config = config or {}
        self._load_config()
        
        self.data_dir = StarTools.get_data_dir("astrbot_plugin_log_analyzer")
        os.makedirs(self.data_dir, exist_ok=True)
        
        # 统计文件路径
        self.stats_file = os.path.join(self.data_dir, "error_stats.json")
        
        # 监控状态
        self._monitor_task = None
        self._last_position = 0
        self._sent_hashes: Set[str] = set()
        
        # 告警阈值计数器 {keyword_hash: count}
        self._alert_counts: Dict[str, int] = defaultdict(int)
        # 告警时间戳 {keyword_hash: last_alert_time}
        self._alert_timestamps: Dict[str, float] = {}
        # 错误统计数据
        self._error_stats: Dict[str, Dict[str, Any]] = {}
        
        # 平台引用
        self._platform: Optional[Platform] = None
        
        # 加载历史统计数据
        self._load_stats()

    def _load_config(self):
        """加载配置（支持热更新）"""
        self.log_path = self.config.get("log_path") or DEFAULT_LOG_PATH
        self.admins_id: List[str] = self.config.get("admins_id", [])
        self.auto_analyze = self.config.get("auto_analyze", False)
        self.auto_fix = self.config.get("auto_fix", False)
        self.analysis_provider_id = self.config.get("analysis_provider_id", "")
        self.analysis_model_name = self.config.get("analysis_model_name", "")
        
        # 自动监控配置
        self.monitor_enabled = self.config.get("monitor_enabled", False)
        self.monitor_interval = self.config.get("monitor_interval", 30)
        
        # 关键词分级配置
        self.monitor_keywords: List[str] = self.config.get("monitor_keywords", [])
        self.critical_keywords: List[str] = self.config.get("critical_keywords", [])
        self.error_keywords: List[str] = self.config.get("error_keywords", [])
        self.warning_keywords: List[str] = self.config.get("warning_keywords", [])
        
        # 告警阈值配置
        self.alert_threshold = self.config.get("alert_threshold", 1)  # 出现N次才告警
        self.alert_cooldown = self.config.get("alert_cooldown", 300)  # 静默期（秒）

    def _load_stats(self):
        """加载历史统计数据"""
        try:
            if os.path.exists(self.stats_file):
                with open(self.stats_file, "r", encoding="utf-8") as f:
                    self._error_stats = json.load(f)
                logger.info(f"[LogAnalyzer] 加载了 {len(self._error_stats)} 条统计数据")
        except Exception as e:
            logger.error(f"[LogAnalyzer] 加载统计数据失败: {e}")

    def _save_stats(self):
        """保存统计数据"""
        try:
            with open(self.stats_file, "w", encoding="utf-8") as f:
                json.dump(self._error_stats, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"[LogAnalyzer] 保存统计数据失败: {e}")

    def _get_alert_level(self, keyword: str) -> str:
        """获取关键词的告警级别"""
        keyword_lower = keyword.lower()
        for kw in self.critical_keywords:
            if kw.lower() in keyword_lower:
                return "critical"
        for kw in self.error_keywords:
            if kw.lower() in keyword_lower:
                return "error"
        for kw in self.warning_keywords:
            if kw.lower() in keyword_lower:
                return "warning"
        # 默认：包含ERROR/Exception的是error，其他是warning
        if any(kw.lower() in keyword_lower for kw in ["error", "exception", "traceback", "fatal"]):
            return "error"
        return "warning"

    def _update_stats(self, keyword: str, level: str):
        """更新错误统计"""
        now = datetime.now()
        date_key = now.strftime("%Y-%m-%d")
        hour_key = now.strftime("%H")
        
        if keyword not in self._error_stats:
            self._error_stats[keyword] = {
                "total": 0,
                "level": level,
                "first_seen": now.isoformat(),
                "last_seen": now.isoformat(),
                "by_date": {},
                "by_hour": {}
            }
        
        stats = self._error_stats[keyword]
        stats["total"] += 1
        stats["last_seen"] = now.isoformat()
        stats["level"] = level
        
        # 按日期统计
        if date_key not in stats["by_date"]:
            stats["by_date"][date_key] = 0
        stats["by_date"][date_key] += 1
        
        # 按小时统计
        if hour_key not in stats["by_hour"]:
            stats["by_hour"][hour_key] = 0
        stats["by_hour"][hour_key] += 1
        
        # 定期保存
        if stats["total"] % 10 == 0:
            self._save_stats()

    async def _get_platform(self) -> Optional[Platform]:
        """获取平台实例"""
        if self._platform:
            return self._platform
        try:
            platforms = getattr(self.context, "platforms", {})
            if platforms:
                self._platform = list(platforms.values())[0]
                return self._platform
        except Exception as e:
            logger.warning(f"[LogAnalyzer] 获取平台实例失败: {e}")
        return None

    async def _send_to_admin(self, message: str, admin_id: str):
        """发送消息给管理员"""
        platform = await self._get_platform()
        if not platform:
            logger.warning("[LogAnalyzer] 无法获取平台实例，跳过发送")
            return
        
        try:
            session_id = f"aiocqhttp:FriendMessage:{admin_id}"
            await platform.send_by_session(session_id, message)
            logger.info(f"[LogAnalyzer] 已发送日志通知给管理员 {admin_id}")
        except Exception as e:
            logger.error(f"[LogAnalyzer] 发送消息失败: {e}")

    def _hash_keyword(self, keyword: str) -> str:
        """生成关键词的hash"""
        import hashlib
        return hashlib.md5(keyword.encode()).hexdigest()[:16]

    def _should_alert(self, keyword: str) -> bool:
        """判断是否应该告警（考虑阈值和静默期）"""
        keyword_hash = self._hash_keyword(keyword)
        now = time.time()
        
        # 检查静默期
        if keyword_hash in self._alert_timestamps:
            last_alert = self._alert_timestamps[keyword_hash]
            if now - last_alert < self.alert_cooldown:
                return False
        
        # 检查阈值
        self._alert_counts[keyword_hash] += 1
        if self._alert_counts[keyword_hash] < self.alert_threshold:
            return False
        
        # 达到阈值，重置计数器并更新时间戳
        self._alert_counts[keyword_hash] = 0
        self._alert_timestamps[keyword_hash] = now
        return True

    async def _monitor_loop(self):
        """日志监控循环"""
        logger.info(f"[LogAnalyzer] 开始监控日志: {self.log_path}")
        logger.info(f"[LogAnalyzer] 监控关键词: {self.monitor_keywords}")
        logger.info(f"[LogAnalyzer] 告警阈值: {self.alert_threshold}, 静默期: {self.alert_cooldown}秒")
        
        while self.monitor_enabled:
            try:
                await self._check_log_file()
            except Exception as e:
                logger.error(f"[LogAnalyzer] 监控出错: {e}")
            
            await asyncio.sleep(self.monitor_interval)
        
        logger.info("[LogAnalyzer] 监控已停止")

    async def _check_log_file(self):
        """检查日志文件的新增内容"""
        if not os.path.isfile(self.log_path):
            return
        
        try:
            file_size = os.path.getsize(self.log_path)
            if file_size < self._last_position:
                self._last_position = 0
            
            with open(self.log_path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(self._last_position)
                new_lines = f.readlines()
                self._last_position = f.tell()
            
            if not new_lines:
                return
            
            # 检查关键词并按级别分组
            matched_by_level: Dict[str, List[str]] = {
                "critical": [],
                "error": [],
                "warning": [],
                "info": []
            }
            
            for line in new_lines:
                line = line.rstrip()
                if not line:
                    continue
                
                for keyword in self.monitor_keywords:
                    if keyword.lower() in line.lower():
                        level = self._get_alert_level(keyword)
                        
                        # 更新统计
                        self._update_stats(keyword, level)
                        
                        # 检查是否应该告警
                        if self._should_alert(keyword):
                            line_hash = self._hash_keyword(line)
                            if line_hash not in self._sent_hashes:
                                matched_by_level[level].append(line)
                                self._sent_hashes.add(line_hash)
                        break
            
            # 发送告警（按级别从高到低）
            if self.admins_id:
                for level in ["critical", "error", "warning", "info"]:
                    lines = matched_by_level[level]
                    if not lines:
                        continue
                    
                    # 限制每次最多发送10条
                    lines = lines[:10]
                    level_name = ALERT_LEVELS[level]["name"]
                    
                    message = f"{level_name} 检测到 {len(lines)} 条日志：\n\n"
                    message += "\n".join(lines[:5])
                    
                    if len(lines) > 5:
                        message += f"\n\n... 还有 {len(lines) - 5} 条"
                    
                    for admin_id in self.admins_id:
                        await self._send_to_admin(message, admin_id)
                    
                    logger.info(f"[LogAnalyzer] 已发送 {level_name} 告警: {len(lines)} 条")
                
        except Exception as e:
            logger.error(f"[LogAnalyzer] 检查日志文件失败: {e}")

    async def initialize(self):
        """插件初始化时启动监控"""
        if self.monitor_enabled and self.admins_id and self.monitor_keywords:
            self._monitor_task = asyncio.create_task(self._monitor_loop())
            logger.info("[LogAnalyzer] 日志监控已启动")
        else:
            if not self.admins_id:
                logger.warning("[LogAnalyzer] 未配置管理员ID，自动监控未启动")
            elif not self.monitor_keywords:
                logger.warning("[LogAnalyzer] 未配置监控关键词，自动监控未启动")
            else:
                logger.info("[LogAnalyzer] 自动监控未启用")

    async def terminate(self):
        """插件卸载时停止监控并保存统计"""
        self.monitor_enabled = False
        self._save_stats()  # 保存统计数据
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        logger.info("[LogAnalyzer] 插件已卸载，统计数据已保存")

    async def _is_admin(self, event: AstrMessageEvent) -> bool:
        """检查用户是否在管理员列表中"""
        return str(event.get_sender_id()) in self.admins_id

    def _parse_time(self, time_str: str) -> Optional[datetime]:
        """解析时间字符串"""
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%Y-%m-%d",
            "%H:%M:%S",
            "%H:%M",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(time_str, fmt)
                if fmt in ["%H:%M:%S", "%H:%M"]:
                    now = datetime.now()
                    dt = dt.replace(year=now.year, month=now.month, day=now.day)
                return dt
            except ValueError:
                continue
        return None

    def _parse_log_time(self, log_line: str) -> Optional[datetime]:
        """从日志行提取时间戳"""
        match = re.match(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\]", log_line)
        if match:
            try:
                return datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                return None
        return None

    def _extract_logs(
        self,
        keyword: str,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        max_lines: int = 100,
    ) -> List[str]:
        """从日志文件提取匹配关键词的日志行"""
        if not os.path.isfile(self.log_path):
            logger.error(f"[LogAnalyzer] 日志文件不存在: {self.log_path}")
            return []

        results = []
        try:
            with open(self.log_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if since or until:
                        log_time = self._parse_log_time(line)
                        if log_time:
                            if since and log_time < since:
                                continue
                            if until and log_time > until:
                                continue
                    if keyword.lower() in line.lower():
                        results.append(line.rstrip())
                        if len(results) >= max_lines:
                            break
        except Exception as e:
            logger.error(f"[LogAnalyzer] 读取日志失败: {e}")
            return []

        return results

    def _format_time_range(self, since: Optional[datetime], until: Optional[datetime]) -> str:
        """格式化时间范围描述"""
        parts = []
        if since:
            parts.append(f"从 {since.strftime('%Y-%m-%d %H:%M:%S')}")
        if until:
            parts.append(f"到 {until.strftime('%Y-%m-%d %H:%M:%S')}")
        return " ".join(parts) if parts else "全部时间"

    @filter.command("日志监控状态", priority=10001)
    async def cmd_monitor_status(self, event: AstrMessageEvent):
        """查看监控状态"""
        if not await self._is_admin(event):
            yield event.plain_result("⚠️ 没有权限使用此命令")
            event.stop_event()
            return
        
        status = "运行中" if self.monitor_enabled and self._monitor_task else "已停止"
        keywords = ", ".join(self.monitor_keywords) if self.monitor_keywords else "无"
        admins = ", ".join(self.admins_id) if self.admins_id else "无"
        
        # 统计信息
        total_errors = sum(s.get("total", 0) for s in self._error_stats.values())
        
        result = f"📊 日志监控状态\n\n"
        result += f"状态：{status}\n"
        result += f"监控关键词：{keywords}\n"
        result += f"扫描间隔：{self.monitor_interval} 秒\n"
        result += f"告警阈值：{self.alert_threshold} 次\n"
        result += f"静默期：{self.alert_cooldown} 秒\n"
        result += f"管理员：{admins}\n"
        result += f"日志路径：{self.log_path}\n"
        result += f"累计错误：{total_errors} 次"
        
        yield event.plain_result(result)
        event.stop_event()

    @filter.command("日志监控 启动", priority=10001)
    async def cmd_monitor_start(self, event: AstrMessageEvent):
        """启动日志监控"""
        if not await self._is_admin(event):
            yield event.plain_result("⚠️ 没有权限使用此命令")
            event.stop_event()
            return
        
        if self.monitor_enabled and self._monitor_task:
            yield event.plain_result("监控已在运行中")
            event.stop_event()
            return
        
        if not self.admins_id:
            yield event.plain_result("⚠️ 未配置管理员ID，无法启动监控")
            event.stop_event()
            return
        
        if not self.monitor_keywords:
            yield event.plain_result("⚠️ 未配置监控关键词，无法启动监控")
            event.stop_event()
            return
        
        self.monitor_enabled = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        yield event.plain_result(f"✅ 日志监控已启动\n监控关键词：{', '.join(self.monitor_keywords)}")
        event.stop_event()

    @filter.command("日志监控 停止", priority=10001)
    async def cmd_monitor_stop(self, event: AstrMessageEvent):
        """停止日志监控"""
        if not await self._is_admin(event):
            yield event.plain_result("⚠️ 没有权限使用此命令")
            event.stop_event()
            return
        
        self.monitor_enabled = False
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
            self._monitor_task = None
        
        yield event.plain_result("✅ 日志监控已停止")
        event.stop_event()

    @filter.command("日志统计", priority=10001)
    async def cmd_stats(self, event: AstrMessageEvent):
        """查看错误统计"""
        if not await self._is_admin(event):
            yield event.plain_result("⚠️ 没有权限使用此命令")
            event.stop_event()
            return
        
        if not self._error_stats:
            yield event.plain_result("📊 暂无错误统计数据")
            event.stop_event()
            return
        
        # 按总数排序
        sorted_stats = sorted(
            self._error_stats.items(),
            key=lambda x: x[1].get("total", 0),
            reverse=True
        )
        
        result = "📊 错误统计（Top 10）\n\n"
        
        for i, (keyword, stats) in enumerate(sorted_stats[:10], 1):
            total = stats.get("total", 0)
            level = stats.get("level", "warning")
            level_name = ALERT_LEVELS.get(level, {}).get("name", "⚪")
            last_seen = stats.get("last_seen", "未知")
            
            # 格式化最后出现时间
            try:
                last_dt = datetime.fromisoformat(last_seen)
                last_seen_str = last_dt.strftime("%m-%d %H:%M")
            except:
                last_seen_str = "未知"
            
            result += f"{i}. {level_name} {keyword}\n"
            result += f"   次数：{total} | 最后：{last_seen_str}\n\n"
        
        total_errors = sum(s.get("total", 0) for s in self._error_stats.values())
        result += f"总计错误：{total_errors} 次"
        
        yield event.plain_result(result)
        event.stop_event()

    @filter.command("日志统计 清空", priority=10001)
    async def cmd_stats_clear(self, event: AstrMessageEvent):
        """清空错误统计"""
        if not await self._is_admin(event):
            yield event.plain_result("⚠️ 没有权限使用此命令")
            event.stop_event()
            return
        
        self._error_stats.clear()
        self._save_stats()
        
        yield event.plain_result("✅ 错误统计数据已清空")
        event.stop_event()

    @filter.command("日志配置 热更新", priority=10001)
    async def cmd_config_reload(self, event: AstrMessageEvent):
        """热更新配置"""
        if not await self._is_admin(event):
            yield event.plain_result("⚠️ 没有权限使用此命令")
            event.stop_event()
            return
        
        try:
            # 重新加载配置
            self._load_config()
            
            result = "✅ 配置已热更新\n\n"
            result += f"监控关键词：{', '.join(self.monitor_keywords) if self.monitor_keywords else '无'}\n"
            result += f"告警阈值：{self.alert_threshold} 次\n"
            result += f"静默期：{self.alert_cooldown} 秒\n"
            result += f"扫描间隔：{self.monitor_interval} 秒"
            
            yield event.plain_result(result)
        except Exception as e:
            yield event.plain_result(f"❌ 配置热更新失败：{e}")
        
        event.stop_event()

    @filter.command("日志关键词 添加", priority=10001)
    async def cmd_add_keyword(self, event: AstrMessageEvent):
        """添加监控关键词"""
        if not await self._is_admin(event):
            yield event.plain_result("⚠️ 没有权限使用此命令")
            event.stop_event()
            return
        
        text = event.message_str
        text = re.sub(r"^日志关键词 添加\s*", "", text).strip()
        
        if not text:
            yield event.plain_result("格式：日志关键词 添加 关键词\n示例：日志关键词 添加 ConnectionError")
            event.stop_event()
            return
        
        if text in self.monitor_keywords:
            yield event.plain_result(f"关键词「{text}」已存在")
            event.stop_event()
            return
        
        self.monitor_keywords.append(text)
        yield event.plain_result(f"✅ 已添加关键词：{text}\n当前监控关键词：{', '.join(self.monitor_keywords)}")
        event.stop_event()

    @filter.command("日志关键词 删除", priority=10001)
    async def cmd_remove_keyword(self, event: AstrMessageEvent):
        """删除监控关键词"""
        if not await self._is_admin(event):
            yield event.plain_result("⚠️ 没有权限使用此命令")
            event.stop_event()
            return
        
        text = event.message_str
        text = re.sub(r"^日志关键词 删除\s*", "", text).strip()
        
        if not text:
            yield event.plain_result("格式：日志关键词 删除 关键词")
            event.stop_event()
            return
        
        if text not in self.monitor_keywords:
            yield event.plain_result(f"关键词「{text}」不存在")
            event.stop_event()
            return
        
        self.monitor_keywords.remove(text)
        yield event.plain_result(f"✅ 已删除关键词：{text}\n当前监控关键词：{', '.join(self.monitor_keywords)}")
        event.stop_event()

    @filter.command("日志抓取", priority=10001)
    async def cmd_fetch(self, event: AstrMessageEvent):
        """日志抓取 关键词 [--since 时间] [--until 时间]"""
        if not await self._is_admin(event):
            yield event.plain_result("⚠️ 没有权限使用此命令")
            event.stop_event()
            return

        text = event.message_str
        text = re.sub(r"^日志抓取\s*", "", text).strip()
        if not text:
            yield event.plain_result("格式：日志抓取 关键词 [--since 时间] [--until 时间]")
            event.stop_event()
            return

        keyword = ""
        since = None
        until = None

        since_match = re.search(r"--since\s+[\"']?([^\"']+)[\"']?", text)
        if since_match:
            since = self._parse_time(since_match.group(1))
            text = text.replace(since_match.group(0), "").strip()

        until_match = re.search(r"--until\s+[\"']?([^\"']+)[\"']?", text)
        if until_match:
            until = self._parse_time(until_match.group(1))
            text = text.replace(until_match.group(0), "").strip()

        keyword = text.strip()
        if not keyword:
            yield event.plain_result("请指定要搜索的关键词")
            event.stop_event()
            return

        logs = self._extract_logs(keyword, since, until)

        if not logs:
            time_range = self._format_time_range(since, until)
            yield event.plain_result(f"在 {time_range} 范围内没有找到包含「{keyword}」的日志")
            event.stop_event()
            return

        time_range = self._format_time_range(since, until)
        result = f"📋 抓取到 {len(logs)} 条日志（{time_range}）\n\n"
        result += "\n".join(logs[:20])
        if len(logs) > 20:
            result += f"\n\n... 还有 {len(logs) - 20} 条日志未显示"

        yield event.plain_result(result)
        event.stop_event()

    @filter.command("日志分析", priority=10001)
    async def cmd_analyze(self, event: AstrMessageEvent):
        """日志分析 关键词 [--since 时间] [--until 时间]"""
        if not await self._is_admin(event):
            yield event.plain_result("⚠️ 没有权限使用此命令")
            event.stop_event()
            return

        text = event.message_str
        text = re.sub(r"^日志分析\s*", "", text).strip()
        if not text:
            yield event.plain_result("格式：日志分析 关键词 [--since 时间] [--until 时间]")
            event.stop_event()
            return

        keyword = ""
        since = None
        until = None

        since_match = re.search(r"--since\s+[\"']?([^\"']+)[\"']?", text)
        if since_match:
            since = self._parse_time(since_match.group(1))
            text = text.replace(since_match.group(0), "").strip()

        until_match = re.search(r"--until\s+[\"']?([^\"']+)[\"']?", text)
        if until_match:
            until = self._parse_time(until_match.group(1))
            text = text.replace(until_match.group(0), "").strip()

        keyword = text.strip()
        if not keyword:
            yield event.plain_result("请指定要搜索的关键词")
            event.stop_event()
            return

        logs = self._extract_logs(keyword, since, until)

        if not logs:
            time_range = self._format_time_range(since, until)
            yield event.plain_result(f"在 {time_range} 范围内没有找到包含「{keyword}」的日志")
            event.stop_event()
            return

        time_range = self._format_time_range(since, until)
        analysis_prompt = f"""请分析以下 {len(logs)} 条日志（关键词：{keyword}，{time_range}），找出报错原因并给出分析结果：

{chr(10).join(logs[:50])}

请用简洁的语言回答：
1. 主要问题是什么？
2. 可能的原因有哪些？
3. 建议如何解决？
"""
        
        yield event.plain_result(f"🔍 正在分析 {len(logs)} 条日志，请稍等...")
        
        event.should_call_llm(True)
        yield event.plain_result(analysis_prompt)
        event.stop_event()

    @filter.command("日志修复", priority=10001)
    async def cmd_fix(self, event: AstrMessageEvent):
        """日志修复 关键词 [--since 时间] [--until 时间]"""
        if not await self._is_admin(event):
            yield event.plain_result("⚠️ 没有权限使用此命令")
            event.stop_event()
            return

        text = event.message_str
        text = re.sub(r"^日志修复\s*", "", text).strip()
        if not text:
            yield event.plain_result("格式：日志修复 关键词 [--since 时间] [--until 时间]")
            event.stop_event()
            return

        keyword = ""
        since = None
        until = None

        since_match = re.search(r"--since\s+[\"']?([^\"']+)[\"']?", text)
        if since_match:
            since = self._parse_time(since_match.group(1))
            text = text.replace(since_match.group(0), "").strip()

        until_match = re.search(r"--until\s+[\"']?([^\"']+)[\"']?", text)
        if until_match:
            until = self._parse_time(until_match.group(1))
            text = text.replace(until_match.group(0), "").strip()

        keyword = text.strip()
        if not keyword:
            yield event.plain_result("请指定要搜索的关键词")
            event.stop_event()
            return

        logs = self._extract_logs(keyword, since, until)

        if not logs:
            time_range = self._format_time_range(since, until)
            yield event.plain_result(f"在 {time_range} 范围内没有找到包含「{keyword}」的日志")
            event.stop_event()
            return

        time_range = self._format_time_range(since, until)
        fix_prompt = f"""请分析以下 {len(logs)} 条日志（关键词：{keyword}，{time_range}），制定修复方案：

{chr(10).join(logs[:50])}

请按以下格式回答：

## 问题诊断
（描述主要问题）

## 根本原因
（分析可能的原因）

## 修复方案
请提供可执行的 shell 命令来修复这个问题，格式如下：
```bash
# 你的命令
```

## 风险评估
（执行这些命令可能带来的风险）
"""
        
        yield event.plain_result(f"🔍 正在分析并制定修复方案，请稍等...")
        
        event.should_call_llm(True)
        yield event.plain_result(fix_prompt)
        event.stop_event()

    @filter.command("日志执行修复", priority=10001)
    async def cmd_execute_fix(self, event: AstrMessageEvent):
        """执行修复命令（需要用户确认）"""
        if not await self._is_admin(event):
            yield event.plain_result("⚠️ 没有权限使用此命令")
            event.stop_event()
            return

        text = event.message_str
        text = re.sub(r"^日志执行修复\s*", "", text).strip()
        
        if not text:
            yield event.plain_result("格式：日志执行修复 命令\n注意：执行前请确保已理解命令的作用！")
            event.stop_event()
            return

        dangerous_keywords = ["rm -rf", "mkfs", "dd if=", "> /dev/", "chmod 777 /", ":(){ :|:& };:"]
        for dk in dangerous_keywords:
            if dk in text:
                yield event.plain_result(f"⚠️ 危险命令检测！包含「{dk}」，拒绝执行！")
                event.stop_event()
                return

        yield event.plain_result(f"⚠️ 确定要执行以下命令吗？\n\n{text}\n\n再次发送「确认执行」来执行，或发送其他内容取消。")
        event.stop_event()
        return

    @filter.command("确认执行", priority=10001)
    async def cmd_confirm_execute(self, event: AstrMessageEvent):
        """确认执行修复命令"""
        if not await self._is_admin(event):
            yield event.plain_result("⚠️ 没有权限使用此命令")
            event.stop_event()
            return
        
        yield event.plain_result("请先用「日志修复」生成修复方案，再复制命令用「日志执行修复」执行")
        event.stop_event()
        return

    @filter.command("日志路径", priority=10001)
    async def cmd_set_log_path(self, event: AstrMessageEvent):
        """设置日志文件路径"""
        if not await self._is_admin(event):
            yield event.plain_result("⚠️ 没有权限使用此命令")
            event.stop_event()
            return

        text = event.message_str
        text = re.sub(r"^日志路径\s*", "", text).strip()
        
        if not text:
            yield event.plain_result(f"当前日志路径：{self.log_path}\n\n使用「日志路径 /path/to/log」来设置新路径")
            event.stop_event()
            return

        if not os.path.isfile(text):
            yield event.plain_result(f"文件不存在：{text}")
            event.stop_event()
            return

        self.log_path = text
        self._last_position = 0
        yield event.plain_result(f"日志路径已更新为：{text}")
        event.stop_event()
        return
