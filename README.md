# Observable Incident Agent

## Render

Build command:

```text
pip install -r requirements.txt
```

Start command:

```text
uvicorn main:app --host 0.0.0.0 --port $PORT
```

Optional AI environment variables:

- `INCIDENT_AI_API_KEY`: an OpenAI-compatible API key
- `INCIDENT_AI_MODEL`: a low-cost JSON-capable model, such as `gpt-4o-mini`

The submitted base URL is the service origin, for example `https://your-service.onrender.com`.
