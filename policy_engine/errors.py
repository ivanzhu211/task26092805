"""模块异常定义。"""


class PolicyEngineError(Exception):
    """模块内所有异常的基类。"""


class ValidationError(PolicyEngineError):
    """写入数据不合法（如时间段起止相同、网段主机位非 0、节点层级超限等）。"""


class NotFoundError(PolicyEngineError):
    """引用的节点、策略或版本不存在。"""


class NonMonotonicTimeError(PolicyEngineError):
    """写入时间早于上一次写入时间。"""


class ReplayUnavailableError(PolicyEngineError):
    """复盘所需的策略版本已被清理，无法给出确定结果。"""
