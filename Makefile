PY ?= python3
VENV ?= /opt/hornwork-venv
PYTHON := $(VENV)/bin/python
HORNWORK_HOME ?= /opt/hornwork
CONFIG ?= $(HORNWORK_HOME)/config.toml

.PHONY: help setup test run demo check lint clean rules install-service frontend frontend-check

help:
	@echo "make setup            安装系统依赖与 Python 依赖（需 root）"
	@echo "make test             运行 unittest"
	@echo "make run              前台运行 daemon（读取 $(CONFIG)）"
	@echo "make demo             运行演示脚本"
	@echo "make check            环境自检"
	@echo "make frontend         构建 Vue 控制台并拷入 hornwork/web/static/app"
	@echo "make frontend-check   前端 lint + 类型检查 + 单测（需先 npm install）"
	@echo "make clean            清理 __pycache__ 与临时文件"

setup:
	bash scripts/setup.sh

test:
	$(PYTHON) -m unittest discover -s tests -v

run:
	$(PYTHON) -m hornwork.daemon --config $(CONFIG)

demo:
	bash scripts/demo.sh

check:
	bash scripts/check.sh

lint:
	@$(PYTHON) -m compileall -q hornwork || true
	@echo "py_compile 完成"

clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	rm -rf build dist *.egg-info .pytest_cache

rules:
	$(PYTHON) -c "from hornwork.cli import main; raise SystemExit(main(['rules','reload']))"

# ---------------------------------------------------------------------------
# Vue 控制台：构建产物落到 hornwork/web/static/app/，由 Web 线程直接托管
# ---------------------------------------------------------------------------
frontend:
	cd frontend && npm install --no-audit --no-fund
	cd frontend && npm run build
	rm -rf hornwork/web/static/app
	mkdir -p hornwork/web/static/app
	cp -r frontend/dist/. hornwork/web/static/app/
	@echo "控制台已构建：hornwork/web/static/app（重启服务后生效）"

frontend-check:
	cd frontend && npm run lint && npm run typecheck && npm run test
