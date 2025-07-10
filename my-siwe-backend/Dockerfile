# Dockerfile
FROM python:3.13-slim

WORKDIR /app

# Install poetry (or copy requirements.txt)
RUN pip install poetry

COPY poetry.lock pyproject.toml ./

# Install dependencies
RUN poetry config virtualenvs.create false && poetry install --no-dev --no-root

COPY ./app /app/app

# Expose the port the app runs on
EXPOSE 8000

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]