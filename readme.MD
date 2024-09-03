# Homework RD #6

## Build
```cp .env.example .env```

```docker compose -f docker-compose.yaml up -d --build```

```poetry shell```

```poetry install```

### Apply migrations
```alembic upgrade head```

### Run app
```python app --dir_path <path>```