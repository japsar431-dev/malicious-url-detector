import uvicorn
from backend.config import SERVER_HOST, SERVER_PORT, DEBUG

if __name__ == "__main__":
    print("=" * 60)
    print("* Starting HackVortex URL Threat Detector API Server")
    print(f"* Server URL: http://127.0.0.1:{SERVER_PORT}")
    print(f"* Interactive API Docs: http://127.0.0.1:{SERVER_PORT}/docs")
    print("=" * 60)
    uvicorn.run(
        "backend.main:app",
        host=SERVER_HOST,
        port=SERVER_PORT,
        reload=DEBUG,
    )
