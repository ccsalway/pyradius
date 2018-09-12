import logging

logging.basicConfig(level="DEBUG", format="%(asctime)s %(name)s %(levelname)s %(message)s")

serverlog = logging.getLogger('server')
auditlog = logging.getLogger('audit')
