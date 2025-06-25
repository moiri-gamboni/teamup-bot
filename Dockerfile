# Use Python 3.11 slim image for smaller size
FROM python:3.11-slim AS base

# Install uv for fast Python package management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_CACHE_DIR=/tmp/uv-cache

# Create app user for security
RUN addgroup --system --gid 1001 appgroup && \
    adduser --system --uid 1001 --ingroup appgroup appuser

# Set working directory
WORKDIR /app

# Copy dependency files
COPY pyproject.toml uv.lock ./

# Install dependencies using uv
RUN --mount=type=cache,target=/tmp/uv-cache \
    uv sync --frozen --no-dev

# Change ownership of dependencies
RUN chown -R appuser:appgroup /app

# Copy application code
COPY main.py ./

# Fix ownership of the new file only
RUN chown appuser:appgroup main.py

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Run the application
CMD ["uv", "run", "python", "main.py"] 