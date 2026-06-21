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
from astrbot.api.event import AstrMessageEvent, MessageChain, filter
from astrbot.api.platform import Platform
import astrbot.api.message_components as Comp
from astrbot.core.platform.astrbot_message import AstrBotMessage, Group, MessageMember
from astrbot.core.platform.message_type import MessageType
from astrbot.core.platform.platform import PlatformStatus

try:
    from astrbot.core.platform.astr_message_event import MessageSession as MS
except ImportError:
    from astrbot.core.platform.message_session import MessageSession as MS

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


@register("astrbot_plugin_log_analyzer", "小七月", "日志分析器：自动监控、抓取、分析、修复", "v1.4.0")
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
        # 待执行的修复命令 {admin_id: {commands, keyword, timestamp}}
        self._pending_fix_commands: Dict[str, Dict[str, Any]] = {}
        # 分页缓存 {admin_id: {logs, keyword, since, until, timestamp}}
        self._page_cache: Dict[str, Dict[str, Any]] = {}
        
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
        
        # 抓取相关配置
        self.max_fetch_lines = int(self.config.get("max_fetch_lines", 500))  # 最大抓取行数

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
        
        # 定期保存（每 3 次）
        if stats["total"] % 3 == 0:
            self._save_stats()

    async def _send_to_admin(self, message: str, admin_id: str):
        """发送消息给管理员"""
        try:
            chain = MessageChain([Comp.Plain(message)])
            
            # 找到一个正在运行的平台
            platforms = self.context.platform_manager.get_insts()
            target_platform = None
            
            for p in platforms:
                if p.status == PlatformStatus.RUNNING:
                    target_platform = p
                    break
            
            if not target_platform:
                logger.error("[LogAnalyzer] 没有找到运行中的平台")
                return
            
            platform_id = target_platform.meta().id
            logger.info(f"[LogAnalyzer] 使用平台 {platform_id} 发送消息")
            
            # 使用平台的 send_by_session 方法发送
            session_obj = MS(platform_name=platform_id, message_type=MessageType.FRIEND_MESSAGE, session_id=admin_id)
            await target_platform.send_by_session(session_obj, chain)
            logger.info(f"[LogAnalyzer] 已发送日志通知给管理员 {admin_id}")
        except Exception as e:
            logger.error(f"[LogAnalyzer] 发送消息失败: {e}")

    def _hash_keyword(self, keyword: str) -> str:
        """生成关键词的唯一key"""
        return str(keyword)

    def _cleanup_memory(self):
        """清理过期的内存缓存，防止无限增长"""
        now = time.time()
        # 清理超过 2 小时的 sent_hashes（直接全量清空，反正文件轮转后就不需要了）
        if len(self._sent_hashes) > 5000:
            logger.info(f"[LogAnalyzer] 清理 _sent_hashes（{len(self._sent_hashes)} 条）")
            self._sent_hashes.clear()
        # 清理超过 1 小时的告警计数器
        expired_hashes = [h for h, ts in self._alert_timestamps.items() if now - ts > 3600]
        for h in expired_hashes:
            self._alert_counts.pop(h, None)
            self._alert_timestamps.pop(h, None)
        if expired_hashes:
            logger.info(f"[LogAnalyzer] 清理了 {len(expired_hashes)} 条过期告警记录")
        # 清理超过 10 分钟的 pending_fix_commands
        expired_fix = [uid for uid, d in self._pending_fix_commands.items() if now - d.get("timestamp", 0) > 600]
        for uid in expired_fix:
            del self._pending_fix_commands[uid]
        # 清理过期的 page_cache
        expired_cache = [uid for uid, d in self._page_cache.items() if now - d.get("timestamp", 0) > 600]
        for uid in expired_cache:
            del self._page_cache[uid]

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
        
        cycle_count = 0
        while self.monitor_enabled:
            try:
                await self._check_log_file()
            except Exception as e:
                logger.error(f"[LogAnalyzer] 监控出错: {e}")
            
            # 每 100 轮清理一次内存缓存
            cycle_count += 1
            if cycle_count >= 100:
                self._cleanup_memory()
                cycle_count = 0
            
            await asyncio.sleep(self.monitor_interval)
        
        logger.info("[LogAnalyzer] 监控已停止")

    async def _analyze_logs_with_ai(self, logs: List[str], keyword: str) -> Optional[str]:
        """使用AI分析日志"""
        try:
            # 构造分析提示
            log_text = "\n".join(logs[:20])  # 限制日志数量
            prompt = f"""请用一句话简要分析以下日志问题（关键词：{keyword}）：

{log_text}

格式：问题：xxx，原因：xxx，建议：xxx
"""
            
            # 获取LLM provider
            provider = None
            if self.analysis_provider_id:
                provider = self.context.get_provider_by_id(self.analysis_provider_id)
            
            if not provider:
                # 尝试获取默认provider
                provider = self.context.get_using_provider()
            
            if not provider:
                logger.warning("[LogAnalyzer] 没有可用的LLM provider，跳过AI分析")
                return None
            
            # 调用LLM分析
            model = self.analysis_model_name or None
            response = await provider.text_chat(prompt, model=model)
            
            if response and hasattr(response, 'completion_text'):
                return response.completion_text
            elif isinstance(response, str):
                return response
            
            return None
        except Exception as e:
            logger.error(f"[LogAnalyzer] AI分析失败: {e}")
            return None

    async def _generate_fix_suggestion(self, logs: List[str], keyword: str) -> Optional[str]:
        """生成修复建议"""
        try:
            log_text = "\n".join(logs[:10])
            fix_prompt = f"""请分析以下日志（关键词：{keyword}），制定修复方案：

{log_text}

请提供可执行的 shell 命令来修复这个问题，只返回命令，不要有其他内容：
```bash
# 你的命令
```
"""
            
            # 获取LLM provider
            provider = None
            if self.analysis_provider_id:
                provider = self.context.get_provider_by_id(self.analysis_provider_id)
            
            if not provider:
                provider = self.context.get_using_provider()
            
            if not provider:
                return None
            
            model = self.analysis_model_name or None
            response = await provider.text_chat(fix_prompt, model=model)
            
            if response and hasattr(response, 'completion_text'):
                return response.completion_text
            elif isinstance(response, str):
                return response
            
            return None
        except Exception as e:
            logger.error(f"[LogAnalyzer] 生成修复建议失败: {e}")
            return None

    def _extract_commands(self, text: str) -> List[str]:
        """从文本中提取shell命令"""
        # 提取 ```bash ... ``` 中的命令
        pattern = r"```(?:bash|sh)?\s*\n(.*?)\n```"
        matches = re.findall(pattern, text, re.DOTALL)
        
        commands = []
        for match in matches:
            lines = match.strip().split('\n')
            for line in lines:
                line = line.strip()
                # 跳过注释和空行
                if line and not line.startswith('#'):
                    commands.append(line)
        
        return commands

    async def _execute_fix_command(self, command: str, admin_id: str) -> str:
        """使用Computer功能执行修复命令"""
        try:
            from astrbot.core.computer.computer_client import get_booter
            
            # 获取 Computer booter
            session_id = f"{admin_id}:FriendMessage:{admin_id}"
            booter = await get_booter(self.context, session_id)
            
            if not booter:
                return "❌ Computer 功能未启用，请先开启 AstrBot 的电脑功能"
            
            logger.info(f"[LogAnalyzer] 执行修复命令: {command}")
            result = await booter.shell.exec(command)
            
            stdout = result.get("stdout", "") or result.get("output", "")
            stderr = result.get("stderr", "") or result.get("error", "")
            success = result.get("success", False)
            
            output = f"{'✅ 命令执行成功' if success else '❌ 命令执行失败'}\n\n"
            if stdout:
                output += f"输出:\n{stdout}\n"
            if stderr:
                output += f"错误:\n{stderr}\n"
            
            return output
        except Exception as e:
            logger.error(f"[LogAnalyzer] 执行命令失败: {e}")
            return f"❌ 执行命令失败: {e}"

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
            matched_keywords: Set[str] = set()
            
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
                                matched_keywords.add(keyword)
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
                
                # 自动分析功能
                if self.auto_analyze and matched_keywords:
                    logger.info("[LogAnalyzer] 自动分析已启用，开始AI分析...")
                    for keyword in matched_keywords:
                        # 获取包含该关键词的日志
                        keyword_logs = [line for line in new_lines if keyword.lower() in line.lower()]
                        if keyword_logs:
                            analysis = await self._analyze_logs_with_ai(keyword_logs[:10], keyword)
                            if analysis:
                                analysis_msg = f"🤖 AI 分析结果（关键词：{keyword}）：\n\n{analysis}"
                                for admin_id in self.admins_id:
                                    await self._send_to_admin(analysis_msg, admin_id)
                                logger.info(f"[LogAnalyzer] 已发送AI分析结果: {keyword}")
                
                # 自动修复功能（生成修复建议）
                if self.auto_fix and matched_keywords:
                    logger.info("[LogAnalyzer] 自动修复已启用，生成修复建议...")
                    for keyword in matched_keywords:
                        keyword_logs = [line for line in new_lines if keyword.lower() in line.lower()]
                        if keyword_logs:
                            # 生成修复建议
                            fix_suggestion = await self._generate_fix_suggestion(keyword_logs[:10], keyword)
                            
                            if fix_suggestion:
                                # 提取命令
                                commands = self._extract_commands(fix_suggestion)
                                
                                if commands:
                                    # 发送修复建议并询问是否执行
                                    fix_msg = f"🔧 修复建议（关键词：{keyword}）：\n\n{fix_suggestion}\n\n\n⚠️ 发送「确认执行修复」自动执行以上命令，或忽略此消息。"
                                    
                                    # 存储待执行的命令
                                    for admin_id in self.admins_id:
                                        self._pending_fix_commands[admin_id] = {
                                            "commands": commands,
                                            "keyword": keyword,
                                            "timestamp": time.time()
                                        }
                                        await self._send_to_admin(fix_msg, admin_id)
                                    
                                    logger.info(f"[LogAnalyzer] 已发送修复建议: {keyword}, 命令数: {len(commands)}")
                                else:
                                    # 没有提取到命令，发送原始建议
                                    fix_msg = f"🔧 修复建议（关键词：{keyword}）：\n\n{fix_suggestion}"
                                    for admin_id in self.admins_id:
                                        await self._send_to_admin(fix_msg, admin_id)
                                    logger.info(f"[LogAnalyzer] 已发送修复建议: {keyword}")
                
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
        """解析时间字符串，支持不补零的月日（如 2026-6-21）"""
        # 先尝试标准格式
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
        
        # 正则兜底：支持 2026-6-21、2026-6-21 13:57、2026-6-21 13:57:30 等不补零格式
        m = re.match(
            r"^(\d{4})-(\d{1,2})-(\d{1,2})"
            r"(?:\s+(\d{1,2}):(\d{1,2})(?::(\d{1,2}))?)?$",
            time_str.strip(),
        )
        if m:
            y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
            h = int(m.group(4)) if m.group(4) else 0
            mi = int(m.group(5)) if m.group(5) else 0
            s = int(m.group(6)) if m.group(6) else 0
            return datetime(y, mo, d, h, mi, s)
        
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
        """从日志文件提取匹配关键词的日志行
        
        当指定 since/until 时：按"日志条目"模式匹配 ——
        识别以时间戳开头的行作为条目头，关键词只匹配条目头，
        匹配成功则输出整个条目（含后续堆栈行），直到遇到下一条目头。
        
        无 since/until 时：全文逐行匹配（原有行为）。
        """
        if not os.path.isfile(self.log_path):
            logger.error(f"[LogAnalyzer] 日志文件不存在: {self.log_path}")
            return []
        
        if since or until:
            lines, _ = self._extract_log_entries(keyword, since, until, max_entries=max_lines)
            return lines
        
        # 无时间参数：原有全文逐行匹配
        results = []
        try:
            with open(self.log_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if keyword.lower() in line.lower():
                        results.append(line.rstrip())
                        if len(results) >= max_lines:
                            break
        except Exception as e:
            logger.error(f"[LogAnalyzer] 读取日志失败: {e}")
            return []

        return results
    
    def _extract_log_entries(
        self,
        keyword: str,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        max_entries: int = 100,
    ):
        """按"日志条目"抓取：关键词只匹配条目头部，但输出完整条目。
        
        Returns:
            (lines, count): (所有匹配行的列表, 匹配到的条目数量)
        """
        results = []
        matched = 0
        
        try:
            # 有时间过滤时，从尾部读取（性能优化：避免全量扫描）
            if since or until:
                lines = self._read_last_lines(n=self.max_fetch_lines * 5)
            else:
                with open(self.log_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = [l.rstrip() for l in f]
            
            cur_lines = []
            cur_time = None
            cur_head = ""
            
            for line in lines:
                s = line.rstrip() if not isinstance(line, str) else line
                t = self._parse_log_time(s)
                
                if t:
                    if cur_head:
                        if self._entry_matches(cur_head, keyword, cur_time, since, until):
                            results.append("\n".join(cur_lines))
                            matched += 1
                            if matched >= max_entries:
                                return results, matched
                    cur_lines = [s]
                    cur_time = t
                    cur_head = s
                else:
                    if cur_head:
                        cur_lines.append(s)
            
            if cur_head:
                if self._entry_matches(cur_head, keyword, cur_time, since, until):
                    results.append("\n".join(cur_lines))
                    matched += 1
        except Exception as e:
            logger.error(f"[LogAnalyzer] 读取日志失败: {e}")
            return [], 0
        
        return results, matched
    
    def _entry_matches(
        self,
        head_line: str,
        keyword: str,
        entry_time: Optional[datetime],
        since: Optional[datetime],
        until: Optional[datetime],
    ) -> bool:
        """检查一个日志条目头部是否匹配关键词 + 时间范围"""
        # 时间过滤
        if entry_time:
            if since and entry_time < since:
                return False
            if until and entry_time > until:
                return False
        # 关键词匹配头部
        if keyword.lower() in head_line.lower():
            return True
        return False

    def _format_time_range(self, since: Optional[datetime], until: Optional[datetime]) -> str:
        """格式化时间范围描述"""
        parts = []
        if since:
            parts.append(f"从 {since.strftime('%Y-%m-%d %H:%M:%S')}")
        if until:
            parts.append(f"到 {until.strftime('%Y-%m-%d %H:%M:%S')}")
        return " ".join(parts) if parts else "全部时间"

    def _parse_command_args(self, text: str, command_name: str) -> Dict[str, Any]:
        """统一解析日志命令的参数（--since/--until/--page）
        
        Returns: {"keyword": str, "since": datetime|None, "until": datetime|None, "page": int}
        """
        # 去掉命令前缀
        cleaned = re.sub(r"^[%#/!?\s]*" + re.escape(command_name) + r"\s*", "", text).strip()
        
        page = 1
        since = None
        until = None
        
        # 解析 --page
        page_match = re.search(r"--page\s+(\d+)", cleaned)
        if page_match:
            page = int(page_match.group(1))
            cleaned = cleaned.replace(page_match.group(0), "").strip()
        
        # 解析 --since（支持带引号的时间）
        since_match = re.search(r"""--since\s+["']?([^"']+)["']?""", cleaned)
        if since_match:
            since = self._parse_time(since_match.group(1))
            cleaned = cleaned.replace(since_match.group(0), "").strip()
        
        # 解析 --until
        until_match = re.search(r"""--until\s+["']?([^"']+)["']?""", cleaned)
        if until_match:
            until = self._parse_time(until_match.group(1))
            cleaned = cleaned.replace(until_match.group(0), "").strip()
        
        return {"keyword": cleaned.strip(), "since": since, "until": until, "page": page}

    def _read_last_lines(self, n: int = 2000) -> List[str]:
        """从文件末尾读取最后 N 行（高性能，适合时间过滤查询）"""
        if not os.path.isfile(self.log_path):
            return []
        try:
            file_size = os.path.getsize(self.log_path)
            chunk_size = min(file_size, 512 * 1024)  # 最多读 512KB
            with open(self.log_path, "rb") as f:
                f.seek(max(0, file_size - chunk_size))
                raw = f.read()
            text = raw.decode("utf-8", errors="ignore")
            all_lines = text.split("\n")
            # 如果 chunk 不是文件开头，第一行可能是不完整的
            if file_size > chunk_size:
                all_lines = all_lines[1:]  # 丢弃可能不完整的第一行
            return [l for l in all_lines[-n:] if l.strip()]
        except Exception as e:
            logger.error(f"[LogAnalyzer] 尾部读取失败: {e}")
            return []

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
        """日志抓取 关键词 [--since 时间] [--until 时间] [--page N]"""
        if not await self._is_admin(event):
            yield event.plain_result("⚠️ 没有权限使用此命令")
            event.stop_event()
            return

        text = event.message_str
        args = self._parse_command_args(text, "日志抓取")
        keyword = args["keyword"]
        since = args["since"]
        until = args["until"]
        page = args["page"]
        
        if not keyword:
            yield event.plain_result("格式：日志抓取 关键词 [--since 时间] [--until 时间] [--page N]")
            event.stop_event()
            return

        admin_id = str(event.get_sender_id())
        
                # 检查缓存：相同关键词+时间范围+5分钟内可用缓存翻页
        cache_key = f"{keyword}_{since}_{until}"
        _entry_count = 0
        is_cached = False
        cached = self._page_cache.get(admin_id)
        if cached and cached.get("cache_key") == cache_key:
            if time.time() - cached.get("timestamp", 0) < 300:
                logs = cached["logs"]
                _entry_count = cached.get("entry_count", 0)
                is_cached = True
            else:
                del self._page_cache[admin_id]
                logs = self._extract_logs(keyword, since, until, max_lines=self.max_fetch_lines)
        else:
            logs = self._extract_logs(keyword, since, until, max_lines=self.max_fetch_lines)

        if not logs:
            time_range = self._format_time_range(since, until)
            yield event.plain_result(f"在 {time_range} 范围内没有找到包含「{keyword}」的日志")
            event.stop_event()
            return

        # 首次提取时缓存结果并统计条目数
        if not is_cached:
            if since or until:
                _, _entry_count = self._extract_log_entries(keyword, since, until, max_entries=self.max_fetch_lines)
            
            self._page_cache[admin_id] = {
                "logs": logs,
                "cache_key": cache_key,
                "keyword": keyword,
                "since": since,
                "until": until,
                "timestamp": time.time(),
                "entry_count": _entry_count
            }
        # 重建翻页用的原始参数字符串
        page_since_str = since.strftime("%Y-%m-%d %H:%M") if since else ""
        page_until_str = until.strftime("%Y-%m-%d %H:%M") if until else ""

        # 条目模式每页5条完整日志，行模式每页20行
        PAGE_SIZE = 5 if (since or until) else 20
        total_pages = (len(logs) + PAGE_SIZE - 1) // PAGE_SIZE
        page = max(1, min(page, total_pages))
        start = (page - 1) * PAGE_SIZE
        end = min(start + PAGE_SIZE, len(logs))

        time_range = self._format_time_range(since, until)
        ec_str = f" | {_entry_count} 个条目" if _entry_count else ""
        result = f"📋 抓取到 {len(logs)} 行日志{ec_str}（{time_range}）"
        result += f" | 第 {page}/{total_pages} 页"
        if page < total_pages:
            extra_args = ""
            if page_since_str:
                extra_args += f" --since \"{page_since_str}\""
            if page_until_str:
                extra_args += f" --until \"{page_until_str}\""
            result += f"\n💡 发送「日志抓取 {keyword}{extra_args} --page {page+1}」翻下一页"
        result += "\n\n"
        result += "\n".join(logs[start:end])

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
        args = self._parse_command_args(text, "日志分析")
        keyword = args["keyword"]
        since = args["since"]
        until = args["until"]
        
        if not keyword:
            yield event.plain_result("格式：日志分析 关键词 [--since 时间] [--until 时间]")
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
        args = self._parse_command_args(text, "日志修复")
        keyword = args["keyword"]
        since = args["since"]
        until = args["until"]
        
        if not keyword:
            yield event.plain_result("格式：日志修复 关键词 [--since 时间] [--until 时间]")
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

        # 危险命令拦截（set 提高查找效率）
        DANGEROUS_COMMANDS = {"rm -rf", "mkfs", "dd if=", "> /dev/", "chmod 777 /", ":(){ :|:& };:", "mv / ", "rm -f /"}
        cmd_lower = text.lower()
        for dk in DANGEROUS_COMMANDS:
            if dk in cmd_lower:
                yield event.plain_result(f"⚠️ 危险命令检测！包含「{dk}」，拒绝执行！")
                event.stop_event()
                return
        # 长度限制 + 混淆检测
        if len(text) > 500:
            yield event.plain_result("⚠️ 命令过长（>500字符），拒绝执行！")
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

    @filter.command("确认执行修复", priority=10001)
    async def cmd_confirm_fix(self, event: AstrMessageEvent):
        """确认执行自动修复命令"""
        if not await self._is_admin(event):
            yield event.plain_result("⚠️ 没有权限使用此命令")
            event.stop_event()
            return
        
        admin_id = str(event.get_sender_id())
        
        # 检查是否有待执行的命令
        if admin_id not in self._pending_fix_commands:
            yield event.plain_result("⚠️ 没有待执行的修复命令")
            event.stop_event()
            return
        
        pending = self._pending_fix_commands[admin_id]
        commands = pending.get("commands", [])
        keyword = pending.get("keyword", "")
        timestamp = pending.get("timestamp", 0)
        
        # 检查是否超时（5分钟）
        if time.time() - timestamp > 300:
            del self._pending_fix_commands[admin_id]
            yield event.plain_result("⚠️ 修复命令已超时，请重新生成")
            event.stop_event()
            return
        
        if not commands:
            del self._pending_fix_commands[admin_id]
            yield event.plain_result("⚠️ 没有可执行的命令")
            event.stop_event()
            return
        
        # 执行命令
        yield event.plain_result(f"🔧 开始执行 {len(commands)} 个修复命令...")
        
        results = []
        for i, cmd in enumerate(commands, 1):
            logger.info(f"[LogAnalyzer] 执行修复命令 {i}/{len(commands)}: {cmd}")
            result = await self._execute_fix_command(cmd, admin_id)
            results.append(f"命令 {i}: {cmd}\n{result}")
        
        # 清除待执行命令
        del self._pending_fix_commands[admin_id]
        
        # 发送执行结果
        result_msg = f"🔧 修复执行完成（关键词：{keyword}）\n\n" + "\n\n".join(results)
        yield event.plain_result(result_msg)
        event.stop_event()

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
