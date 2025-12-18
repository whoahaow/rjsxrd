"""GitHub API handler for uploading files."""

from github import Github, Auth, GithubException
import time
import os
from typing import Optional
from config.settings import GITHUB_TOKEN, REPO_NAME
from utils.logger import log, updated_files, _UPDATED_FILES_LOCK


class GitHubHandler:
    def __init__(self):
        if GITHUB_TOKEN:
            self.g = Github(auth=Auth.Token(GITHUB_TOKEN))
        else:
            self.g = Github()

        self.repo = self.g.get_repo(REPO_NAME)

        # Check GitHub API limits
        try:
            remaining, limit = self.g.rate_limiting
            if remaining < 100:
                log(f"Внимание: осталось {remaining}/{limit} запросов к GitHub API")
            else:
                log(f"Доступно запросов к GitHub API: {remaining}/{limit}")
        except Exception as e:
            log(f"Не удалось проверить лимиты GitHub API: {e}")

    def upload_file(self, local_path: str, remote_path: str):
        """Uploads a local file to GitHub repository."""
        if not self._file_exists(local_path):
            log(f"Файл {local_path} не найден.")
            return

        with open(local_path, "r", encoding="utf-8") as file:
            content = file.read()

        max_retries = 5

        for attempt in range(1, max_retries + 1):
            try:
                # Try to get the existing file to check for changes
                try:
                    file_in_repo = self.repo.get_contents(remote_path)
                    current_sha = file_in_repo.sha
                except GithubException as e_get:
                    if getattr(e_get, "status", None) == 404:
                        # File doesn't exist, create it
                        basename = self._get_basename(remote_path)
                        self.repo.create_file(
                            path=remote_path,
                            message=f"Первый коммит {basename}: {self._get_timestamp()}",
                            content=content,
                        )
                        log(f"Файл {remote_path} создан.")
                        self._add_to_updated_files(remote_path)
                        return
                    else:
                        msg = e_get.data.get("message", str(e_get))
                        log(f"Ошибка при получении {remote_path}: {msg}")
                        return

                try:
                    remote_content = file_in_repo.decoded_content.decode("utf-8", errors="replace")
                    if remote_content == content:
                        log(f"Изменений для {remote_path} нет.")
                        return
                except Exception:
                    pass

                # Update the file
                basename = self._get_basename(remote_path)
                try:
                    self.repo.update_file(
                        path=remote_path,
                        message=f"Обновление {basename}: {self._get_timestamp()}",
                        content=content,
                        sha=current_sha,
                    )
                    log(f"Файл {remote_path} обновлён в репозитории.")
                    self._add_to_updated_files(remote_path)
                    return
                except GithubException as e_upd:
                    if getattr(e_upd, "status", None) == 409:
                        if attempt < max_retries:
                            wait_time = 0.5 * (2 ** (attempt - 1))
                            log(f"Конфликт SHA для {remote_path}, попытка {attempt}/{max_retries}, ждем {wait_time} сек")
                            time.sleep(wait_time)
                            continue
                        else:
                            log(f"Не удалось обновить {remote_path} после {max_retries} попыток")
                            return
                    else:
                        msg = e_upd.data.get("message", str(e_upd))
                        log(f"Ошибка при загрузке {remote_path}: {msg}")
                        return

            except Exception as e_general:
                short_msg = str(e_general)
                if len(short_msg) > 200:
                    short_msg = short_msg[:200] + "…"
                log(f"Непредвиденная ошибка при обновлении {remote_path}: {short_msg}")
                return

        log(f"Не удалось обновить {remote_path} после {max_retries} попыток")

    def update_readme_table(self, remote_paths: list, urls: list, extra_url: str = ""):
        """Updates the README.md table with file information."""
        from config.settings import OFFSET
        try:
            # Get current README.md
            try:
                readme_file = self.repo.get_contents("README.md")
                old_content = readme_file.decoded_content.decode("utf-8")
            except GithubException as e:
                if e.status == 404:
                    log("README.md не найден в репозитории")
                    return
                else:
                    log(f"Ошибка при получении README.md: {e}")
                    return

            # Split time and date
            time_part, date_part = OFFSET.split(" | ")

            # Create new table
            table_header = "| № | Файл | Источник | Время | Дата |\n|--|--|--|--|--|"
            table_rows = []

            # Process regular URLs (files 1-25)
            for i, (remote_path, url) in enumerate(zip(remote_paths[:-1], urls), 1):
                filename = f"{i}.txt"
                raw_file_url = f"https://github.com/{REPO_NAME}/raw/refs/heads/main/githubmirror/{i}.txt"
                source_name = self._extract_source_name(url)
                source_column = f"[{source_name}]({url})"

                # Check if file was updated in this run
                if i in updated_files:
                    update_time = time_part
                    update_date = date_part
                else:
                    # Try to find time from old table
                    import re
                    pattern = rf"\|\s*{i}\s*\|\s*\[`{filename}`\].*?\|.*?\|\s*(.*?)\s*\|\s*(.*?)\s*\|"
                    match = re.search(pattern, old_content)
                    if match:
                        update_time = match.group(1).strip() if match.group(1).strip() else "Никогда"
                        update_date = match.group(2).strip() if match.group(2).strip() else "Никогда"
                    else:
                        update_time = "Никогда"
                        update_date = "Никогда"

                table_rows.append(f"| {i} | [`{filename}`]({raw_file_url}) | {source_column} | {update_time} | {update_date} |")

            # Process bypass files (SNI/CIDR bypass configs)
            # Get bypass files from bypass subdirectory
            import os
            bypass_files = []
            bypass_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "githubmirror", "bypass")
            if os.path.exists(bypass_dir):
                for f in os.listdir(bypass_dir):
                    if f.startswith("bypass-") and f.endswith(".txt") and f != "bypass-all.txt":
                        try:
                            # Extract the number after "bypass-" (before ".txt")
                            num_str = f.replace("bypass-", "").replace(".txt", "")
                            num = int(num_str)
                            bypass_files.append(num)
                        except ValueError:
                            continue

            # Process bypass config files (bypass-1.txt, bypass-2.txt, etc.)
            for i in sorted(bypass_files):
                remote_path = f"githubmirror/bypass/bypass-{i}.txt"
                filename = f"bypass-{i}.txt"
                raw_file_url = f"https://github.com/{REPO_NAME}/raw/refs/heads/main/githubmirror/bypass/bypass-{i}.txt"

                source_column = "Разделенный файл для обхода SNI/CIDR"

                if i in updated_files:
                    update_time = time_part
                    update_date = date_part
                else:
                    import re
                    pattern = rf"\|\s*bypass-{i}\s*\|\s*\[`{filename}`\].*?\|.*?\|\s*(.*?)\s*\|\s*(.*?)\s*\|"
                    match = re.search(pattern, old_content)
                    if match:
                        update_time = match.group(1).strip() if match.group(1).strip() else "Никогда"
                        update_date = match.group(2).strip() if match.group(2).strip() else "Никогда"
                    else:
                        update_time = "Никогда"
                        update_date = "Никогда"

                table_rows.append(f"| bypass-{i} | [`{filename}`]({raw_file_url}) | {source_column} | {update_time} | {update_date} |")

            # Handle bypass-all.txt specifically
            if os.path.exists(os.path.join(githubmirror_path, "bypass", "bypass-all.txt")):
                remote_path = "githubmirror/bypass/bypass-all.txt"
                filename = "bypass-all.txt"
                raw_file_url = f"https://github.com/{REPO_NAME}/raw/refs/heads/main/githubmirror/bypass/bypass-all.txt"
                source_name = "Обход SNI/CIDR белых списков (все конфиги)"
                source_column = f"[{source_name}]({raw_file_url})"

                if 99999 in updated_files:  # Using a large number to represent bypass-all.txt in updated_files
                    update_time = time_part
                    update_date = date_part
                else:
                    import re
                    pattern = rf"\|\s*bypass-all\s*\|\s*\[`{filename}`\].*?\|.*?\|\s*(.*?)\s*\|\s*(.*?)\s*\|"
                    match = re.search(pattern, old_content)
                    if match:
                        update_time = match.group(1).strip() if match.group(1).strip() else "Никогда"
                        update_date = match.group(2).strip() if match.group(2).strip() else "Никогда"
                    else:
                        update_time = "Никогда"
                        update_date = "Никогда"

                table_rows.append(f"| bypass-all | [`{filename}`]({raw_file_url}) | {source_column} | {update_time} | {update_date} |")

            new_table = table_header + "\n" + "\n".join(table_rows)

            # Replace table in README.md
            import re
            table_pattern = r"\| № \| Файл \| Источник \| Время \| Дата \|[\s\S]*?\|--\|--\|--\|--\|--\|[\s\S]*?(\n\n## |$)"
            new_content = re.sub(table_pattern, new_table + r"\1", old_content)

            if new_content != old_content:
                self.repo.update_file(
                    path="README.md",
                    message="Обновление таблицы в README.md",
                    content=new_content,
                    sha=readme_file.sha
                )
                log("Таблица в README.md обновлена")
            else:
                log("Таблица в README.md не требует изменений")

        except Exception as e:
            log(f"Ошибка при обновлении README.md: {e}")

    def _file_exists(self, path: str) -> bool:
        """Checks if a local file exists."""
        return os.path.exists(path)

    def _get_basename(self, remote_path: str) -> str:
        """Extracts the basename from a remote path."""
        return os.path.basename(remote_path)

    def _get_timestamp(self) -> str:
        """Gets the current timestamp."""
        from config.settings import OFFSET
        return OFFSET

    def _extract_source_name(self, url: str) -> str:
        """Extracts source name from URL."""
        from utils.logger import extract_source_name
        return extract_source_name(url)

    def _add_to_updated_files(self, remote_path: str):
        """Adds a file to the updated files set."""
        path_parts = remote_path.split('/')
        if len(path_parts) >= 2:
            folder_or_filename = path_parts[1]
            if folder_or_filename == "bypass":
                # Handle bypass files (e.g., bypass/bypass-1.txt, bypass/bypass-all.txt)
                if len(path_parts) >= 3:
                    bypass_filename = path_parts[2]
                    if bypass_filename.startswith("bypass-") and bypass_filename.endswith(".txt"):
                        if bypass_filename == "bypass-all.txt":
                            # Use a special number to represent bypass-all.txt in updated_files
                            file_index = 99999
                        else:
                            # Extract number from bypass-N.txt
                            num_str = bypass_filename.replace("bypass-", "").replace(".txt", "")
                            try:
                                file_index = int(num_str)
                            except ValueError:
                                file_index = -1  # Invalid bypass file
                    else:
                        # Default to -1 if it's not a bypass file
                        file_index = -1
                else:
                    file_index = -1
            else:
                # Handle default files (e.g., default/1.txt, etc.)
                try:
                    file_index = int(folder_or_filename.split('.')[0])
                except ValueError:
                    file_index = -1
        else:
            file_index = -1

        if file_index != -1:
            with _UPDATED_FILES_LOCK:
                updated_files.add(file_index)