from __future__ import annotations

import argparse
import json

from app.crawler.playwright_crawler import crawl_url_sync


def main() -> None:
    parser = argparse.ArgumentParser(description="Sandbox crawl CLI")
    parser.add_argument("--url", required=True)
    parser.add_argument("--depth", default="standard")
    parser.add_argument("--task-id", required=True)
    args = parser.parse_args()

    artifacts = crawl_url_sync(args.url, args.depth, args.task_id)
    print(json.dumps(artifacts.to_dict(), ensure_ascii=False))


if __name__ == "__main__":
    main()
