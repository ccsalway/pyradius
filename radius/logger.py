import logging

logging.basicConfig(level="DEBUG", format="%(asctime)s %(name)s %(levelname)s %(message)s")

serverlog = logging.getLogger('server')
clientlog = logging.getLogger('client')
auditlog = logging.getLogger('audit')
