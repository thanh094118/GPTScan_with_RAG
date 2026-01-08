import logging
from config import LOGGING_FORMAT, LOGGING_LEVEL
# logging.basicConfig(level=LOGGING_LEVEL, format=LOGGING_FORMAT)

from rich.logging import RichHandler

logging.basicConfig(
    level=LOGGING_LEVEL, format=LOGGING_FORMAT, handlers=[RichHandler(rich_tracebacks=True)]
)

logger = logging.getLogger(__name__)
import json
import tasks
import rich

console = rich.get_console()

def welcome():
    console.print("""[bold blue]                                             
[/bold blue]""")

if __name__ == '__main__':
    welcome()
    tasks.simple_cli()
