from app.engine.registry import ParserRegistry
from app.engine.parsers.ssh_parser import SSHAuthParser
from app.engine.parsers.http_parser import HTTPWebParser
from app.engine.parsers.zeek_parser import ZeekTSVParser

# Auto-register default parser strategies
ParserRegistry.register(SSHAuthParser())
ParserRegistry.register(HTTPWebParser())
ParserRegistry.register(ZeekTSVParser())
