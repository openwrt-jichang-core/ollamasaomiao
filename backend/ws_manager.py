"""
WebSocket 广播管理器。

设计要点（对应审计里提出的三个问题）：
1. 每个连接一个独立的 asyncio.Queue + 独立的发送协程（_sender_loop），
   互相之间没有共享的阻塞点——一个慢客户端只会撑满自己的队列，
   不会拖慢 broadcast() 给其他连接推送的速度。
2. 队列满时丢弃最旧的一条腾位置（而不是 await 等它被消费，也不是无限增长），
   彻底避免"慢客户端 = 内存无限增长"或"慢客户端 = 广播阻塞"两种雪崩模式。
3. disconnect() 在 finally 里被路由函数无条件调用，保证 WebSocketDisconnect
   （标签页关闭 / 弱网断线 / 主动刷新）发生时，连接表和对应的发送协程
   一定会被清理，不会有"无主协程"或连接表条目泄露。
"""
import asyncio
import contextlib
import logging

logger = logging.getLogger("ws_manager")


class ConnectionManager:
    def __init__(self, queue_maxsize: int = 200):
        self._connections: dict[int, tuple] = {}
        self._lock = asyncio.Lock()
        self._queue_maxsize = queue_maxsize

    async def connect(self, ws):
        await ws.accept()
        q: asyncio.Queue = asyncio.Queue(maxsize=self._queue_maxsize)
        task = asyncio.create_task(self._sender_loop(ws, q))
        async with self._lock:
            self._connections[id(ws)] = (ws, q, task)
        return q, task

    async def disconnect(self, ws):
        async with self._lock:
            entry = self._connections.pop(id(ws), None)
        if entry is None:
            return
        _, _, task = entry
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    async def _sender_loop(self, ws, q: asyncio.Queue):
        try:
            while True:
                msg = await q.get()
                await ws.send_json(msg)
        except asyncio.CancelledError:
            raise
        except Exception:
            # 发送失败通常意味着连接已经死了（对端断开但服务端还没收到 close 帧）。
            # 不往外抛，让 accept 侧的 receive 循环自然感知到断开并触发清理。
            logger.info("ws sender loop ended (client likely disconnected)")

    async def broadcast(self, msg: dict):
        async with self._lock:
            items = list(self._connections.values())
        for ws, q, _task in items:
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                with contextlib.suppress(asyncio.QueueEmpty):
                    q.get_nowait()
                with contextlib.suppress(asyncio.QueueFull):
                    q.put_nowait(msg)

    def connection_count(self) -> int:
        return len(self._connections)


manager = ConnectionManager()

# 主事件循环引用，供扫描线程（非 asyncio 世界）跨线程安全地触发广播。
_MAIN_LOOP = None


def capture_running_loop():
    global _MAIN_LOOP
    _MAIN_LOOP = asyncio.get_running_loop()


def push_from_thread(msg: dict):
    """扫描线程调用这个函数来广播，绝不能在扫描线程里直接 await 协程。"""
    if _MAIN_LOOP is None:
        return
    try:
        asyncio.run_coroutine_threadsafe(manager.broadcast(msg), _MAIN_LOOP)
    except RuntimeError:
        # 事件循环已关闭（例如进程正在退出），安静地丢弃即可
        pass
