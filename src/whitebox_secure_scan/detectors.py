from pathlib import Path
import re
from .repository import SourceFile


MAX_MANIFEST_BYTES = 2_000_000

FRAMEWORK_MARKERS = {
    "Django": ["django", "rest_framework"],
    "Flask": ["flask"],
    "FastAPI": ["fastapi"],
    "Starlette": ["starlette"],
    "SQLAlchemy": ["sqlalchemy"],
    "Celery": ["celery"],
    "Express": ["express"],
    "NestJS": ["@nestjs"],
    "Next.js": ["next"],
    "Fastify": ["fastify"],
    "Koa": ["koa"],
    "Prisma": ["@prisma"],
    "Sequelize": ["sequelize"],
    "TypeORM": ["typeorm"],
    "Mongoose": ["mongoose"],
    "Axios": ["axios"],
    "Spring Boot": ["spring-boot", "org.springframework"],
    "Spring Security": ["spring-security"],
    "Hibernate": ["hibernate"],
    "JPA": ["jakarta.persistence", "javax.persistence"],
    "MyBatis": ["mybatis"],
    "net/http": ["net/http"],
    "Gin": ["github.com/gin-gonic/gin"],
    "Echo": ["github.com/labstack/echo"],
    "Fiber": ["github.com/gofiber/fiber"],
    "GORM": ["gorm.io/gorm"],
}


def detect_frameworks(files: list[SourceFile], root: Path) -> list[str]:
    text = "\n".join(f.text for f in files) + "\n"
    for name in (
        "requirements.txt",
        "pyproject.toml",
        "package.json",
        "pom.xml",
        "build.gradle",
        "go.mod",
    ):
        p = root / name
        if p.is_file() and not p.is_symlink() and p.stat().st_size <= MAX_MANIFEST_BYTES:
            text += p.read_text(encoding="utf-8", errors="replace") + "\n"
    return sorted(
        name
        for name, markers in FRAMEWORK_MARKERS.items()
        if any(
            re.search(rf"(?i)(?<![A-Za-z0-9_]){re.escape(marker)}(?![A-Za-z0-9_])", text)
            for marker in markers
        )
    )


def detect_languages(files: list[SourceFile]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for file in files:
        counts[file.language] = counts.get(file.language, 0) + 1
    return counts
