import multiprocessing
import os

# Gunicorn config variables
bind = "127.0.0.1:8000"
workers = 2  # For t3.micro/t4g.micro (2 vCPU usually, or 1 vCPU burstable)
# t4g.micro has 2 vCPUs. t3.micro has 2 vCPUs.
# Recommended workers = (2 x num_cores) + 1, but for micro instances, keeping it low is safer for memory.
# Let's go with 3? Or just 2 to be safe on RAM (1GB).
# 2 workers is generally enough for low traffic and 1GB RAM.
workers = 2 
worker_class = "uvicorn.workers.UvicornWorker"
timeout = 120
keepalive = 5
max_requests = 1000
max_requests_jitter = 50
accesslog = "/var/log/freeyo/access.log"
errorlog = "/var/log/freeyo/error.log"
loglevel = "info"
daemon = False
