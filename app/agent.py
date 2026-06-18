# 当前版本 agent 与 worker 使用同一套检测逻辑。
# 后续多地域部署时，只需要通过 AGENT_NAME / AGENT_REGION 区分来源。
from worker import main

if __name__ == "__main__":
    main()
