from anket.core import *

class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT
    }

    def format(self, record):
        color = self.COLORS.get(record.levelname, Fore.WHITE)
        record.levelname = f"{color}{record.levelname}{Style.RESET_ALL}"
        return super().format(record)

logger = logging.getLogger()
handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter('%(levelname)s - %(filename)s:%(lineno)d - %(message)s'))
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)
logging.getLogger('asyncio').setLevel(logging.WARNING)

init(autoreset=True)
